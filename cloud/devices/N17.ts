import HADevice from './base'
import { Device as Thinq2Device } from '../thinq2/device'
import { DeviceDiscovery, type Connection } from '../homeassistant'
import { type Metadata } from '../thinq'
import { allowExtendedType } from '@/util/casting'
import AABBDevice from './aabb_device'
import log from '@/util/logging'

// LG LDNPQ445S dishwasher, reporting modelName "N17" (deviceType 204, BEKEN_BK7234). "N17" is much
// shorter than the usual LG model codes, so it is probably a board/platform identifier rather than an
// appliance model — expect other appliances to match this same string.
//
// The protocol is the AABB dialect also spoken by the H11 dishwasher (upstream PR #139), from which
// the record layout below was originally derived. Every decoded field and every command has since
// been confirmed on a live N17 (device ae4a343b, firmware clip_bkn_v1.9.226), using bridge mode to
// capture LG's own cloud traffic and the LG app as ground truth.
//
// Commands, captured from LG's cloud driving this appliance (2026-08-23):
//
//   F0 26 10 <course> <delayHours> 00 <opt3> <opt4> 00   start
//                                        ^ 0x04 extra dry, 0x08 high temp, 0x80 steam
//   F0 26 13                                             pause
//   F0 26 14                                             resume
//   F0 26 11                                             cancel (runs the ~67 s process-0x63 drain)
//   F0 26 12                                             power off (straight to STANDBY, no drain)
//   F0 26 <rinse> 00 <opts> 40 00 <light> 00 00          settings snapshot (captured 2026-09-01, see
//                                                        the SETTING_* constants). Byte 2 doubles as
//                                                        the "opcode": rinse levels 0-4 never collide
//                                                        with the action opcodes 0x10-0x16.
//
// 0x11 and 0x12 are different actions, not two forms of cancel: the app's Cancel Cycle control sends
// 0x11 in every machine state — observed even for a delayed cycle that never took on water, where the
// drain still ran — while its separate power button sends 0x12 (H11 calls it Immediate Power Off).
// So Cancel here always sends 0x11, and Power Off is its own button.
//
// All five were observed working, and the cancel was additionally replayed from this host with no LG
// cloud in the loop. The command's course and option bytes override whatever the panel had selected.
// Delay start and the download cycle were confirmed together by an app-driven "Tub Clean, 1 hour
// delay" remote start (F0 26 10 0B 01 00 00 00 00), which put the appliance into a delay counting
// down 00:59, 00:58, ... Note LG did NOT set H11's opt4 bit 0x40 for the download cycle, so neither
// do we.
//
// What is deliberately NOT offered, because each would be shipping a guess into a machine that moves
// water:
//   - Extra rinse (H11's opt4 levels). This model does not have the feature: its panel has no extra
//     rinse button and the app's option list is exactly Steam / High Temp / Extra Dry. Not a gap.
//   - Wake-up (F0 26 16), never seen here.
//   - Every course code outside those observed running on this appliance.
//
// Two constraints on the write path, both observed rather than assumed:
//   - Start is refused unless the LATEST status has the remote-start bit (flags2 0x02) set. The
//     appliance clears that bit itself when a cycle ends, so it has to be re-armed at the panel for
//     each wash — readiness must be re-checked before every start, not once.
//   - Commands are unconfirmable. The 0x32 0x00 acknowledgement echoes only the opcode it is acking —
//     no success/failure signal — and LG's own cloud was seen re-sending an ignored start 5 s later.
//     The status frames are the only evidence a command took effect.
//
// Frame envelope, after AABBDevice strips "AA <len>" and "<checksum> BB":
//   buf[0] = 0x32   constant across every frame observed (the dishwasher class byte; the dryers use 0x30)
//   buf[1] = type
//
// Frame types, from a bench capture plus live deployment runs. The appliance does not transmit
// continuously: it goes quiet for minutes at a time and then emits a burst lasting about a minute,
// during which 0x0A arrives every 1-5s and 0x3E every 4-6s.
//   0xEB  status, single record — the reply to the 0xF0ED status query, which LG's cloud sends and
//         start() reproduces on connect. Decoded below.
//   0xEC  status, two stacked records (previous, then current) — volunteered on change, unsolicited:
//         one frame per panel action, and once a minute during a wash as remain-time ticks. An idle
//         appliance has no changes to report and sends none, so short captures can miss this opcode
//         entirely. Records are 0x1D long, like 0xEB — not H11's 0x18. Decoded below.
//   0x3E  energy statistics. Decoded below.
//   0x0A  Two record variants alternating within a burst, 87 and 88 bytes. Body carries a few numeric
//         fields, an incrementing counter, then a length-prefixed ASCII list of component ids
//         ("204-1", "DW-3-3", ...) — a parts manifest, not fault codes. Not decoded. Two oddities:
//         its length byte is 0xFF regardless of the real frame size, and it is the only frame type
//         here that FAILS this repo's AABB checksum (0x31, 0x72 and 0x3E all pass). Neither matters
//         to us, since AABBDevice keys off the 0xAA/0xBB delimiters rather than length or checksum.
//   0x31  79-byte component manifest, ASCII serials (SAA30007301 / SAA30003801 / SAA44901001). Sent on
//         connect and again after a wash cancel or completion. Not decoded, and it does not need to be: the same
//         bytes arrive as "pcbInfo" in the device_log message, and the serials also appear, stripped
//         of their SAA prefix, as the "packageId" in appInfo.
//   0x88  30-byte packed form of the same part numbers, on connect. Not decoded.
//   0x72  9-byte marker, one frame 1-2s ahead of each wash start/cancel. Not decoded.
//   0x27  3-byte marker, seen once shortly after a settings write. Not decoded.
//   0x00  the opcode-echo ack: replies to the cloud's 0xF0 0x0B keepalive (echoing its payload) and
//         acks commands (32 00 26 00 observed for a settings write). Not decoded.

const DISHWASHER_STATES: Record<number, string> = {
    // 0x00 is not in H11's table; it is what this appliance settles on after STANDBY, so: powered down.
    0: 'OFF',
    1: 'INITIAL',
    2: 'RUNNING',
    3: 'PAUSE',
    4: 'STANDBY',
    // Also absent from H11's table. Observed live at cycle end: the instant the dry finished, state
    // and process both went 0x05, held ~30 s, then dropped to STANDBY with the course byte cleared.
    5: 'COMPLETE',
}

// Inherited from H11 and corroborated on an N17 by the LG app itself: a full cycle ran as course 0x01
// with the app's own screen naming it "Auto" mid-wash, and a panel session showed 0x05 with Normal
// selected — exactly this mapping.
const COURSES: Record<number, string> = {
    0x00: 'OFF',
    0x01: 'AUTO',
    0x02: 'HEAVY/INTENSIVE',
    // Owner-labelled on 2026-08-23: a remote start commanding course 0x04 ran the panel's Turbo cycle.
    // Absent from H11's table.
    0x04: 'TURBO',
    0x05: 'NORMAL/ECO',
    0x08: 'EXPRESS',
    0x09: 'MACHINE_CLEAN',
    0x0b: 'DOWNLOAD_CYCLE',
    0x10: 'SILENT_NIGHT',
    0x12: 'ONE_HOUR',
}

// This model's own catalogue, from the LG app's "Manage Download Cycles" screen, where each cycle
// carries a "P" number. P1 Tub Clean is wire-confirmed: a remote start of the downloaded cycle
// reported i20 = 0x01 while the app had Tub Clean loaded. The other eight are LG's own numbering from
// that screen with the P1 anchor matching; a code outside the table publishes 'unknown'.
//
// H11's table (0x05 GREASY_TABLEWARE, 0x0d MACHINE_CLEAN, 0x0f PLASTIC_WASH) is NOT used: it is sparse
// where this catalogue is nine consecutive numbers, and it names cycles this appliance does not offer.
// Under this mapping H11's 0x05 would be Casseroles, so inheriting it would have mislabelled cycles.
const SMART_COURSES: Record<number, string> = {
    0x01: 'TUB_CLEAN',
    0x02: 'EXPRESS',
    0x03: 'RINSE',
    0x04: 'POTS_AND_PANS',
    0x05: 'CASSEROLES',
    0x06: 'GLASSWARE',
    0x07: 'NIGHT_CARE',
    0x08: 'DELICATE',
    0x09: 'REFRESH',
}

const CLASS_BYTE = 0x32
const STATUS_FRAME_TYPE = 0xec
const SINGLE_STATUS_FRAME_TYPE = 0xeb
const STATISTICS_FRAME_TYPE = 0x3e

// 0xEB is 37 bytes on the wire, carrying a single 29-byte record behind a 2-byte header of
// [marker][length]. The marker is 0x00 or 0x08 (both observed, with no difference in the record either
// way), so only the length is checked.
//
// 0xEC is the two-stacked-records form: [marker][len][previous record] [marker][len][current record].
// On an N17 the records are 0x1D long, the same record 0xEB carries; on H11 they are 0x18. Both
// lengths are accepted.
const SINGLE_RECORD_LEN = 0x1d
const H11_RECORD_LEN = 0x18

// Offsets within a record body, inherited from H11 (PR #139). Confirmed on an N17 across two live
// sessions — a 0xEB panel session (ten frames, byte-identical except at indexes 0, 5, 11, 12, 16) and
// the 0xEC stream of the 2026-08-22 wash, checked against the LG app as ground truth:
//
//   i0   state    0x01 INITIAL -> 0x02 RUNNING -> 0x05 COMPLETE -> 0x04 STANDBY -> 0x00, tracking the
//                 panel and the cycle
//   i1   process  cycle phase while RUNNING: 0x02 -> 0x03 -> 0x04 across the 2026-08-22 cycle, then
//                 0x05 alongside state 0x05 at completion. 0x02 and 0x04 are app-labelled — the LG app
//                 read "Washing" and "Drying" respectively while the byte held those values; 0x03 sits
//                 between them (rinse, inferred, no screenshot). H11 uses this byte only for 0x63 =
//                 cancelling.
//   i3/4 course time, hours/minutes: 0x02 0x21 = 2h33m for the whole 2026-08-22 cycle — exactly the
//                 app's 9:12pm start -> 11:45pm estimated end
//   i5   course   0x01 while the LG app displayed "Auto", 0x05 while Normal was selected on the panel
//   i7/8 remain time, hours/minutes: counted down once a minute in step with the app (frame said 1:01
//                 where the app had shown 1:04 a few minutes earlier)
//   i11  flags1   bit 0x02 is H11's door-open bit, confirmed as the door moved. Three settings bits,
//                 each labelled by toggling the setting in the LG app (2026-09-01) and watching this
//                 byte in the readback: 0x40 clean indicator light, 0x20 tub clean reminder, 0x10
//                 automatic selection. Bit 0x04 tracks rinse aid level > 0 — it cleared when the
//                 level was set to 0 and returned at level 4. Not published; the level itself is.
//   i12  options  bit 0x04 extra dry, bit 0x08 high temp. Both are owner-labelled from remote starts on
//                 2026-08-23: a wash started with only Extra Dry selected reported 0x04, and one with
//                 only High Temp reported 0x08. They match the option bits H11 sets in its own start
//                 command (targetExtraDry -> 0x04, targetHighTemp -> 0x08). Cleared to 0x00 on cancel.
//                 Bit 0x80 is steam, from a "Normal with Steam" remote start; H11 has no steam option,
//                 so nothing about this bit is inherited. That completes the three options the app
//                 exposes — Steam, High Temp, Extra Dry — and matches the screenshot of a wash with all
//                 three OFF reading 0x00.
//                 Bit 0x01 is not an option at all — it tracks delay start. It was set for the whole of
//                 an 11-hour delayed wash, stayed set (with the stale delay bytes) after that wash was
//                 cancelled, and cleared to 0x00 together with i9/i10 the moment a fresh no-delay Normal
//                 wash was selected. Not published.
//   i9/10 delay start, hours then minutes. H11 maps only the hours byte; i10 read 0x00 in every capture
//                 until an 11-hour delay was set from the panel on 2026-08-23, when the pair counted
//                 0x0B 0x00 -> 0x0A 0x3B -> 0x0A 0x3A (11:00 -> 10:59 -> 10:58). Published as total
//                 minutes, matching course_time and remain_time in this same handler. Publishing hours
//                 alone the way H11 does is not just imprecise, it is misleading: a 1-hour delay reads
//                 "0" for its first 59 minutes and never appears to move.
//   i13  rinse aid dispenser level, matching the app's Settings screen at 2, 0 and 4. i14 is where
//                 H11 reads its salt level; it has read 0x00 in every N17 frame and the US app has no
//                 salt setting, so it is not exposed.
//   i15  flags2   0x02 remote start (below). Bit 0x80 is the Chime Sound setting, app-labelled by
//                 toggling it: 0x89 <-> 0x09.
//   i16  opt2     0x46 -> 0x44, bit 0x02, which H11 does not map. Tracks course selection. Also bit
//                 0x08: set 3 s before the door auto-opened for drying (05:23:58Z vs 05:24:01Z, with
//                 the app then showing "Door is open." mid-dry) — reads like the auto-open dry
//                 engaging. Not published. Bit 0x04 is the End of Cycle tone setting, app-labelled by
//                 toggling it: 0x46 <-> 0x42.
//   i21  bit 0x40 is the Status Indicator Light setting, app-labelled by toggling it. The only byte
//                 past i16 ever seen to move.
const STATE_OFFSET = 0
const PROCESS_OFFSET = 1
const COURSE_TIME_HOUR_OFFSET = 3
const COURSE_TIME_MIN_OFFSET = 4
const COURSE_OFFSET = 5
const REMAIN_TIME_HOUR_OFFSET = 7
const REMAIN_TIME_MIN_OFFSET = 8
const DELAY_START_OFFSET = 9
const DELAY_START_MIN_OFFSET = 10
const FLAGS1_OFFSET = 11
const FLAG1_DOOR_OPEN = 0x02
const FLAG1_TUB_CLEAN_REMINDER = 0x20
const FLAG1_CLEAN_INDICATOR_LIGHT = 0x40
const FLAG1_AUTOMATIC_SELECTION = 0x10
const OPTIONS_OFFSET = 12
const OPTION_EXTRA_DRY = 0x04
const OPTION_HIGH_TEMP = 0x08
// Steam. H11 has no steam option at all, so this bit is N17-only: an owner-labelled remote start of
// "Normal with Steam" carried opt3 0x80 and the appliance reported options 0x80.
const OPTION_STEAM = 0x80
const RINSE_LEVEL_OFFSET = 13
const FLAGS2_OFFSET = 15
const FLAG2_REMOTE_START = 0x02
const FLAG2_CHIME_SOUND = 0x80
const OPT2_OFFSET = 16
const OPT2_END_OF_CYCLE_TONE = 0x04
const SMART_COURSE_OFFSET = 20
const STATUS_LIGHT_OFFSET = 21
const STATUS_LIGHT_ON = 0x40

// Option bits of byte 4 of the settings snapshot command. Captured live (2026-09-01) by toggling
// every control on the LG app's Settings screen one at a time with bridge logging on: each bit was
// seen both set and cleared, and each change was echoed back in the next status record. The bit
// positions differ from the record's readback bits above, so the two sets of constants stay separate.
const SETTING_CHIME_SOUND = 0x04
const SETTING_END_OF_CYCLE_TONE = 0x40
const SETTING_TUB_CLEAN_REMINDER = 0x01
const SETTING_CLEAN_INDICATOR_LIGHT = 0x08
const SETTING_AUTOMATIC_SELECTION = 0x20

// MQTT property name -> settings-cache key, for the six on/off settings.
const SETTING_SWITCH_KEYS = {
    chime_sound: 'chimeSound',
    end_of_cycle_tone: 'endOfCycleTone',
    tub_clean_reminder: 'tubCleanReminder',
    clean_indicator_light: 'cleanIndicatorLight',
    automatic_selection: 'automaticSelection',
    status_indicator_light: 'statusIndicatorLight',
} as const

// H11 treats this process code as "cancelling", and reports power off for it so the power switch does
// not bounce mid-cancel. Kept because it also feeds the state sensor here. Owner-labelled on this
// appliance 2026-08-23: the machine reports "draining" for the whole span this byte reads 0x63, so it
// is a real drain-out phase, not a bookkeeping state. The state byte stays 0x02 RUNNING throughout, and
// the cycle ends at 0x04 STANDBY without ever passing through 0x05 — 0x05 means finished normally.
const PROCESS_CANCELLING = 0x63

// The delay-start wait. Cancel routing depends on it: this is the one running state with no water in
// the machine, and the app sends power-off rather than cancel-drain for it.
const PROCESS_DELAYED_START = 0x01

// Courses the Start Course button may command — those seen running on this appliance, no more. A code
// from H11's wider table that this model maps differently would start the wrong cycle. 0x0b runs
// whatever cycle is loaded in the panel's Downloaded slot; the appliance then reports the real cycle in
// i5 and its catalogue number in i20 (a Tub Clean run reported i5 0x09 MACHINE_CLEAN, i20 0x01).
const COURSE_DOWNLOAD_CYCLE = 0x0b
const START_COURSES = [0x01, 0x02, 0x04, 0x05, COURSE_DOWNLOAD_CYCLE]

// Cycle phase, from the process byte. WASHING and DRYING are app-labelled (see the offsets comment);
// RINSING is the inferred name for the phase between them. 0x00 is what the byte reads whenever the
// machine is not running a cycle.
const PROCESSES: Record<number, string> = {
    0x00: 'NONE',
    // Observed once, 2026-08-23: an 11-hour delayed Normal wash started from the panel sat at state
    // 0x02 RUNNING with this process code while the delay counted down, and a wash with no delay went
    // straight from 0x00 to 0x02 WASHING. So the machine reports itself running for the whole delay
    // window and this byte is what separates waiting from washing.
    [PROCESS_DELAYED_START]: 'DELAYED_START',
    0x02: 'WASHING',
    0x03: 'RINSING',
    0x04: 'DRYING',
    0x05: 'COMPLETE',
    [PROCESS_CANCELLING]: 'CANCELLING',
}

export default class Device extends AABBDevice {
    readonly deviceConfig: DeviceDiscovery

    constructor(HA: Connection, thinq: Thinq2Device, meta: Metadata) {
        super(HA, thinq)
        this.deviceConfig = HADevice.config(meta, { name: 'LG Dishwasher' })

        this.setConfig(
            allowExtendedType({
                ...this.deviceConfig,
                components: {
                    state: {
                        platform: 'sensor',
                        icon: 'mdi:dishwasher',
                        device_class: 'enum',
                        options: [...Object.values(DISHWASHER_STATES), 'CANCELLING'],
                        unique_id: '$deviceid-state',
                        state_topic: '$this/state',
                        name: 'State',
                    },
                    course: {
                        platform: 'sensor',
                        icon: 'mdi:dishwasher',
                        device_class: 'enum',
                        options: [...Object.values(COURSES), ...Object.values(SMART_COURSES)],
                        unique_id: '$deviceid-course',
                        state_topic: '$this/course',
                        name: 'Course',
                    },
                    process: {
                        platform: 'sensor',
                        icon: 'mdi:progress-clock',
                        device_class: 'enum',
                        options: Object.values(PROCESSES),
                        unique_id: '$deviceid-process',
                        state_topic: '$this/process',
                        name: 'Process',
                    },
                    remain_time: {
                        platform: 'sensor',
                        icon: 'mdi:timer-sand',
                        unique_id: '$deviceid-remain_time',
                        state_topic: '$this/remain_time',
                        name: 'Remain Time',
                        unit_of_measurement: 'min',
                    },
                    course_time: {
                        platform: 'sensor',
                        icon: 'mdi:timer',
                        unique_id: '$deviceid-course_time',
                        state_topic: '$this/course_time',
                        name: 'Course Time',
                        unit_of_measurement: 'min',
                    },
                    // Minutes, like course_time and remain_time — not hours. H11 publishes only the
                    // hours byte, which on this appliance means a 10:58 delay reads "10" and a 0:59
                    // one reads "0" and never moves while it counts down. i10 carries the minutes.
                    delay_start: {
                        platform: 'sensor',
                        icon: 'mdi:clock-fast',
                        unique_id: '$deviceid-delay_start',
                        state_topic: '$this/delay_start',
                        name: 'Delay Start',
                        unit_of_measurement: 'min',
                    },
                    door: {
                        platform: 'binary_sensor',
                        device_class: 'door',
                        unique_id: '$deviceid-door',
                        state_topic: '$this/door',
                        name: 'Door',
                        payload_on: 'OPEN',
                        payload_off: 'CLOSE',
                    },
                    energy_consumption: {
                        platform: 'sensor',
                        device_class: 'energy',
                        state_class: 'total_increasing',
                        unique_id: '$deviceid-energy_consumption',
                        state_topic: '$this/energy_consumption',
                        name: 'Energy Consumption',
                        unit_of_measurement: 'Wh',
                        icon: 'mdi:flash',
                    },
                    extra_dry: {
                        platform: 'binary_sensor',
                        icon: 'mdi:weather-sunny',
                        unique_id: '$deviceid-extra_dry',
                        state_topic: '$this/extra_dry',
                        name: 'Extra Dry',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    high_temp: {
                        platform: 'binary_sensor',
                        icon: 'mdi:thermometer-high',
                        unique_id: '$deviceid-high_temp',
                        state_topic: '$this/high_temp',
                        name: 'High Temp',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    steam: {
                        platform: 'binary_sensor',
                        icon: 'mdi:kettle-steam',
                        unique_id: '$deviceid-steam',
                        state_topic: '$this/steam',
                        name: 'Steam',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    remote_start: {
                        platform: 'binary_sensor',
                        icon: 'mdi:remote',
                        unique_id: '$deviceid-remote_start',
                        state_topic: '$this/remote_start',
                        name: 'Remote Start',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    // Settings, mirrored from the appliance's own readback (see the offset comments)
                    // and written as a full snapshot of the cached state. Names are the LG app's own.
                    // `optimistic` hides the ~2 s until the appliance echoes the change back.
                    rinse_level: {
                        platform: 'number',
                        icon: 'mdi:water-plus',
                        entity_category: 'config',
                        unique_id: '$deviceid-rinse_level',
                        state_topic: '$this/rinse_level',
                        command_topic: '$this/rinse_level/set',
                        name: 'Rinse Aid Dispenser Level',
                        min: 0,
                        max: 4,
                        step: 1,
                        optimistic: true,
                    },
                    chime_sound: {
                        platform: 'switch',
                        icon: 'mdi:volume-high',
                        entity_category: 'config',
                        unique_id: '$deviceid-chime_sound',
                        state_topic: '$this/chime_sound',
                        command_topic: '$this/chime_sound/set',
                        name: 'Chime Sound',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                        optimistic: true,
                    },
                    end_of_cycle_tone: {
                        platform: 'switch',
                        icon: 'mdi:music-note',
                        entity_category: 'config',
                        unique_id: '$deviceid-end_of_cycle_tone',
                        state_topic: '$this/end_of_cycle_tone',
                        command_topic: '$this/end_of_cycle_tone/set',
                        name: 'End of Cycle Tone',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                        optimistic: true,
                    },
                    tub_clean_reminder: {
                        platform: 'switch',
                        icon: 'mdi:bell-outline',
                        entity_category: 'config',
                        unique_id: '$deviceid-tub_clean_reminder',
                        state_topic: '$this/tub_clean_reminder',
                        command_topic: '$this/tub_clean_reminder/set',
                        name: 'Tub Clean Reminder',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                        optimistic: true,
                    },
                    clean_indicator_light: {
                        platform: 'switch',
                        icon: 'mdi:lightbulb',
                        entity_category: 'config',
                        unique_id: '$deviceid-clean_indicator_light',
                        state_topic: '$this/clean_indicator_light',
                        command_topic: '$this/clean_indicator_light/set',
                        name: 'Clean Indicator Light',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                        optimistic: true,
                    },
                    automatic_selection: {
                        platform: 'switch',
                        icon: 'mdi:auto-fix',
                        entity_category: 'config',
                        unique_id: '$deviceid-automatic_selection',
                        state_topic: '$this/automatic_selection',
                        command_topic: '$this/automatic_selection/set',
                        name: 'Automatic Selection',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                        optimistic: true,
                    },
                    status_indicator_light: {
                        platform: 'switch',
                        icon: 'mdi:led-on',
                        entity_category: 'config',
                        unique_id: '$deviceid-status_indicator_light',
                        state_topic: '$this/status_indicator_light',
                        command_topic: '$this/status_indicator_light/set',
                        name: 'Status Indicator Light',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                        optimistic: true,
                    },
                    // Controls. Every packet these send was captured from LG's own cloud driving this
                    // appliance (see the command table at the top), so none of it is inferred from H11.
                    // The H11 features never seen on this appliance — extra rinse and wake-up — are
                    // deliberately absent.
                    target_course: {
                        platform: 'select',
                        icon: 'mdi:washing-machine',
                        unique_id: '$deviceid-target_course',
                        state_topic: '$this/target_course',
                        command_topic: '$this/target_course/set',
                        name: 'Target Course',
                        // Only the four codes observed running on this appliance. H11 lists more, but
                        // each of those is an unverified guess here and a wrong code starts the wrong
                        // cycle.
                        options: ['AUTO', 'HEAVY/INTENSIVE', 'TURBO', 'NORMAL/ECO', 'DOWNLOAD_CYCLE'],
                    },
                    // Confirmed as a command on 2026-08-23: a remote start carrying byte 4 = 0x01 put
                    // the appliance into a 1-hour delay that counted down 00:59, 00:58, ... Range is
                    // H11's; only 1 h has been commanded here, and 11 h has been set from the panel.
                    target_delay: {
                        platform: 'number',
                        icon: 'mdi:clock-start',
                        unique_id: '$deviceid-target_delay',
                        state_topic: '$this/target_delay',
                        command_topic: '$this/target_delay/set',
                        name: 'Target Delay Start',
                        min: 0,
                        max: 12,
                        step: 1,
                        unit_of_measurement: 'h',
                    },
                    target_high_temp: {
                        platform: 'switch',
                        icon: 'mdi:thermometer-high',
                        unique_id: '$deviceid-target_high_temp',
                        state_topic: '$this/target_high_temp',
                        command_topic: '$this/target_high_temp/set',
                        name: 'Target High Temp',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    target_extra_dry: {
                        platform: 'switch',
                        icon: 'mdi:weather-sunny',
                        unique_id: '$deviceid-target_extra_dry',
                        state_topic: '$this/target_extra_dry',
                        command_topic: '$this/target_extra_dry/set',
                        name: 'Target Extra Dry',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    target_steam: {
                        platform: 'switch',
                        icon: 'mdi:kettle-steam',
                        unique_id: '$deviceid-target_steam',
                        state_topic: '$this/target_steam',
                        command_topic: '$this/target_steam/set',
                        name: 'Target Steam',
                        payload_on: 'ON',
                        payload_off: 'OFF',
                    },
                    // Unavailable unless the appliance's latest status says remote start is armed. The
                    // bit self-clears when a cycle ends, so this greys out again after every wash and
                    // the panel has to re-arm it — that is the appliance's own interlock, not ours.
                    start_course: {
                        platform: 'button',
                        icon: 'mdi:play-circle',
                        unique_id: '$deviceid-start_course',
                        command_topic: '$this/start_course/set',
                        name: 'Start Course',
                        payload_press: 'PRESS',
                        availability: [
                            { topic: '$this/availability' },
                            { topic: '$rethink/availability' },
                            {
                                topic: '$this/remote_start',
                                payload_available: 'ON',
                                payload_not_available: 'OFF',
                            },
                        ],
                        availability_mode: 'all',
                    },
                    pause: {
                        platform: 'button',
                        icon: 'mdi:pause-circle',
                        unique_id: '$deviceid-pause',
                        command_topic: '$this/pause/set',
                        name: 'Pause',
                        payload_press: 'PRESS',
                    },
                    resume: {
                        platform: 'button',
                        icon: 'mdi:play-pause',
                        unique_id: '$deviceid-resume',
                        command_topic: '$this/resume/set',
                        name: 'Resume',
                        payload_press: 'PRESS',
                    },
                    cancel: {
                        platform: 'button',
                        icon: 'mdi:stop-circle',
                        unique_id: '$deviceid-cancel',
                        command_topic: '$this/cancel/set',
                        name: 'Cancel Cycle',
                        payload_press: 'PRESS',
                    },
                    // 0x12, the app's power button. Distinct from Cancel: it stops without the drain.
                    power_off: {
                        platform: 'button',
                        icon: 'mdi:power',
                        unique_id: '$deviceid-power_off',
                        command_topic: '$this/power_off/set',
                        name: 'Power Off',
                        payload_press: 'PRESS',
                    },
                },
            }),
        )
    }

    // The status query, observed — not guessed: LG's own cloud sends exactly this packet, which is
    // also the family-wide F0ED1121010000001800 the washer, dryer and WashTower handlers in this repo
    // already send, verbatim. The appliance answers with a 0xEB status frame. The trailing 0x18 is
    // not a reply-length field — this appliance's record is 0x1D long.
    start() {
        this.send(Buffer.from('F0ED1121010000001800', 'hex'))

        // Seed the target entities so HA has something to show before the first press.
        this.publishProperty('target_course', COURSES[this.targetCourse])
        this.publishProperty('target_high_temp', this.targetHighTemp ? 'ON' : 'OFF')
        this.publishProperty('target_extra_dry', this.targetExtraDry ? 'ON' : 'OFF')
        this.publishProperty('target_steam', this.targetSteam ? 'ON' : 'OFF')
        this.publishProperty('target_delay', this.targetDelay)
    }

    // What to start, and whether starting is currently allowed. Defaults match the appliance's own
    // power-on default (§17: it highlights AUTO with no options).
    targetCourse = 0x01
    targetHighTemp = false
    targetExtraDry = false
    targetSteam = false
    targetDelay = 0
    remoteStartReady = false

    // The latest settings read back from the appliance; undefined until the first status record.
    settings?: {
        rinseLevel: number
        chimeSound: boolean
        endOfCycleTone: boolean
        tubCleanReminder: boolean
        cleanIndicatorLight: boolean
        automaticSelection: boolean
        statusIndicatorLight: boolean
    }

    // The settings snapshot, byte for byte the shape the app sends: there is no per-setting command,
    // every write carries all of them. Byte 5 was 0x40 in every captured command (H11 maps this byte
    // to its remote-start mode); byte 3 is H11's salt level, a feature this model does not have.
    sendSettings() {
        if (!this.settings) return
        const s = this.settings
        let opts = 0
        if (s.chimeSound) opts |= SETTING_CHIME_SOUND
        if (s.endOfCycleTone) opts |= SETTING_END_OF_CYCLE_TONE
        if (s.tubCleanReminder) opts |= SETTING_TUB_CLEAN_REMINDER
        if (s.cleanIndicatorLight) opts |= SETTING_CLEAN_INDICATOR_LIGHT
        if (s.automaticSelection) opts |= SETTING_AUTOMATIC_SELECTION
        this.send(
            Buffer.from([
                0xf0,
                0x26,
                s.rinseLevel,
                0x00,
                opts,
                0x40,
                0x00,
                s.statusIndicatorLight ? 0x01 : 0x00,
                0x00,
                0x00,
            ]),
        )
    }

    setProperty(prop: string, mqttValue: string) {
        if (prop === 'target_course') {
            const code = Object.keys(COURSES).find((k) => COURSES[Number(k)] === mqttValue)
            // Reject anything not in the select's option list rather than starting a wrong cycle.
            if (code === undefined || !START_COURSES.includes(Number(code))) return
            this.targetCourse = Number(code)
            this.publishProperty('target_course', mqttValue)
        } else if (prop === 'target_high_temp') {
            this.targetHighTemp = mqttValue === 'ON'
            this.publishProperty('target_high_temp', mqttValue)
        } else if (prop === 'target_extra_dry') {
            this.targetExtraDry = mqttValue === 'ON'
            this.publishProperty('target_extra_dry', mqttValue)
        } else if (prop === 'target_steam') {
            this.targetSteam = mqttValue === 'ON'
            this.publishProperty('target_steam', mqttValue)
        } else if (prop === 'target_delay') {
            const hours = parseInt(mqttValue, 10)
            if (isNaN(hours) || hours < 0 || hours > 12) return
            this.targetDelay = hours
            this.publishProperty('target_delay', hours)
        } else if (prop === 'start_course') {
            // HA already hides the button when this is false, but MQTT is not a permission system —
            // anything can publish to the topic, so the interlock is enforced here too.
            if (!this.remoteStartReady) {
                log('N17', 'refusing to start: appliance does not report remote start ready')
                return
            }
            let opt3 = 0
            if (this.targetHighTemp) opt3 |= OPTION_HIGH_TEMP
            if (this.targetExtraDry) opt3 |= OPTION_EXTRA_DRY
            if (this.targetSteam) opt3 |= OPTION_STEAM
            // Bytes 5/7/8 carry options this appliance has never been seen to use; every captured
            // start had them zero, so they stay zero. H11 additionally sets opt4 bit 0x40 for a
            // download cycle, but LG's own download-cycle start sent opt4 = 0x00, so we do not.
            this.send(Buffer.from([0xf0, 0x26, 0x10, this.targetCourse, this.targetDelay, 0x00, opt3, 0x00, 0x00]))
        } else if (prop === 'rinse_level' || prop in SETTING_SWITCH_KEYS) {
            // A settings write is a full snapshot, so the current values must be known first — a
            // snapshot built from defaults would silently overwrite the appliance's other settings.
            if (!this.settings) {
                log('N17', 'refusing settings write: no status record received yet')
                return
            }
            if (prop === 'rinse_level') {
                const level = parseInt(mqttValue, 10)
                if (isNaN(level) || level < 0 || level > 4) return
                this.settings.rinseLevel = level
            } else {
                this.settings[SETTING_SWITCH_KEYS[prop as keyof typeof SETTING_SWITCH_KEYS]] = mqttValue === 'ON'
            }
            this.sendSettings()
        } else if (prop === 'pause') {
            this.send(Buffer.from('F02613', 'hex'))
        } else if (prop === 'resume') {
            this.send(Buffer.from('F02614', 'hex'))
        } else if (prop === 'cancel') {
            this.send(Buffer.from('F02611', 'hex'))
        } else if (prop === 'power_off') {
            this.send(Buffer.from('F02612', 'hex'))
        }
    }

    processAABB(buf: Buffer) {
        if (buf.length < 2 || buf[0] !== CLASS_BYTE) return
        if (buf[1] === SINGLE_STATUS_FRAME_TYPE) return this.processSingleStatus(buf)
        if (buf[1] === STATUS_FRAME_TYPE) return this.processStatus(buf)
        if (buf[1] === STATISTICS_FRAME_TYPE) return this.processStatistics(buf)

        // 0x0A / 0x31 / 0x88 / 0x72 land here.
        log('N17', 'undecoded frame', buf.toString('hex'))
    }

    // Body is "32 3E <delta Wh, 2B> <accumulated Wh, 2B> <sequence>", per PR #139; live traffic pins
    // the field roles:
    //
    //   32 3E 0000 0000 00      idle from boot, 0 Wh
    //   32 3E 0002 0002 01      2 Wh, delta and accumulated moving together
    //
    // On this appliance the sequence byte behaves like a change counter (it stepped exactly when the
    // reading changed, then held across identical frames), not the burst counter PR #139 describes.
    // H11's rule — drop any frame whose sequence repeats — would become wrong if the single-byte
    // counter ever wraps onto a changed reading. publishProperty already collapses repeats without
    // that risk, so the rule is deliberately not reproduced here.
    processStatistics(buf: Buffer) {
        if (buf.length < 7) return
        this.publishProperty('energy_consumption', buf.readUInt16BE(4))
    }

    // The appliance's unsolicited change report, previous record then current — a full wash produces
    // one per minute plus one per panel action. N17 records are 0x1D long; H11's 0x18 form is still
    // accepted.
    processStatus(buf: Buffer) {
        const payloadLen = buf.length - 2
        const halfLen = Math.floor(payloadLen / 2)
        if (halfLen <= 10) return

        // Second half of the payload is the current state; the first half is the previous state.
        const record = buf.subarray(2 + halfLen)
        if (record[1] !== SINGLE_RECORD_LEN && record[1] !== H11_RECORD_LEN) return
        this.publishStatusRecord(record.subarray(2), record[1])
    }

    // The single-record form, and the only status frame this appliance has actually been seen to send.
    // Body is "32 EB <marker> <0x1D> <29-byte record>".
    processSingleStatus(buf: Buffer) {
        if (buf[3] !== SINGLE_RECORD_LEN) return
        this.publishStatusRecord(buf.subarray(4), SINGLE_RECORD_LEN)
    }

    publishStatusRecord(data: Buffer, expectedLen: number) {
        if (data.length < expectedLen) return

        const stateCode = data[STATE_OFFSET]
        const processCode = data[PROCESS_OFFSET]
        const isCancelling = processCode === PROCESS_CANCELLING
        this.publishProperty('state', isCancelling ? 'CANCELLING' : (DISHWASHER_STATES[stateCode] ?? 'unknown'))
        this.publishProperty('process', PROCESSES[processCode] ?? 'unknown')

        // A smart/downloaded course, when one is active, replaces the base course rather than adding to it.
        const smartCourse = data[SMART_COURSE_OFFSET]
        const baseCourse = data[COURSE_OFFSET]
        this.publishProperty(
            'course',
            smartCourse !== 0 ? (SMART_COURSES[smartCourse] ?? 'unknown') : (COURSES[baseCourse] ?? 'unknown'),
        )

        this.publishProperty('course_time', data[COURSE_TIME_HOUR_OFFSET] * 60 + data[COURSE_TIME_MIN_OFFSET])
        this.publishProperty('remain_time', data[REMAIN_TIME_HOUR_OFFSET] * 60 + data[REMAIN_TIME_MIN_OFFSET])
        this.publishProperty('delay_start', data[DELAY_START_OFFSET] * 60 + data[DELAY_START_MIN_OFFSET])
        this.publishProperty('door', data[FLAGS1_OFFSET] & FLAG1_DOOR_OPEN ? 'OPEN' : 'CLOSE')
        this.publishProperty('extra_dry', data[OPTIONS_OFFSET] & OPTION_EXTRA_DRY ? 'ON' : 'OFF')
        this.publishProperty('high_temp', data[OPTIONS_OFFSET] & OPTION_HIGH_TEMP ? 'ON' : 'OFF')
        this.publishProperty('steam', data[OPTIONS_OFFSET] & OPTION_STEAM ? 'ON' : 'OFF')
        this.remoteStartReady = (data[FLAGS2_OFFSET] & FLAG2_REMOTE_START) !== 0
        this.publishProperty('remote_start', this.remoteStartReady ? 'ON' : 'OFF')

        // The settings, echoed by the appliance in every record. This readback is also what arms the
        // write path: until it has run once, settings writes are refused.
        this.settings = {
            rinseLevel: data[RINSE_LEVEL_OFFSET],
            chimeSound: (data[FLAGS2_OFFSET] & FLAG2_CHIME_SOUND) !== 0,
            endOfCycleTone: (data[OPT2_OFFSET] & OPT2_END_OF_CYCLE_TONE) !== 0,
            tubCleanReminder: (data[FLAGS1_OFFSET] & FLAG1_TUB_CLEAN_REMINDER) !== 0,
            cleanIndicatorLight: (data[FLAGS1_OFFSET] & FLAG1_CLEAN_INDICATOR_LIGHT) !== 0,
            automaticSelection: (data[FLAGS1_OFFSET] & FLAG1_AUTOMATIC_SELECTION) !== 0,
            statusIndicatorLight: (data[STATUS_LIGHT_OFFSET] & STATUS_LIGHT_ON) !== 0,
        }
        this.publishProperty('rinse_level', this.settings.rinseLevel)
        this.publishProperty('chime_sound', this.settings.chimeSound ? 'ON' : 'OFF')
        this.publishProperty('end_of_cycle_tone', this.settings.endOfCycleTone ? 'ON' : 'OFF')
        this.publishProperty('tub_clean_reminder', this.settings.tubCleanReminder ? 'ON' : 'OFF')
        this.publishProperty('clean_indicator_light', this.settings.cleanIndicatorLight ? 'ON' : 'OFF')
        this.publishProperty('automatic_selection', this.settings.automaticSelection ? 'ON' : 'OFF')
        this.publishProperty('status_indicator_light', this.settings.statusIndicatorLight ? 'ON' : 'OFF')
    }
}
