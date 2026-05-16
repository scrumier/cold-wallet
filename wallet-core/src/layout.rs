// Screen dimensions (STM32H747I-DISCO)
pub const SCREEN_W: i32 = 800;
pub const SCREEN_H: i32 = 480;

// Welcome
pub const BTN_W: i32         = 300;
pub const BTN_H: i32         = 60;
pub const BTN_X: i32         = (SCREEN_W - BTN_W) / 2;
pub const BTN_NEW_Y: i32     = 170;
pub const BTN_RESTORE_Y: i32 = 270;

// NewWallet nav buttons
pub const NAV_BTN_W: i32  = 160;
pub const NAV_BTN_H: i32  = 50;
pub const NAV_PREV_X: i32 = 40;
pub const NAV_NEXT_X: i32 = SCREEN_W - 40 - NAV_BTN_W;
pub const NAV_BTN_Y: i32  = SCREEN_H - 70;

// QWERTY keyboard
pub const KEY_W: i32    = 65;
pub const KEY_H: i32    = 45;
pub const KEY_GAP: i32  = 5;
pub const KEY_STEP: i32 = KEY_W + KEY_GAP;
pub const ROW_STEP: i32 = KEY_H + KEY_GAP;
pub const KB_Y: i32     = 115;

pub const ROW0_X: i32 = (SCREEN_W - (10 * KEY_W + 9 * KEY_GAP)) / 2;
pub const ROW1_X: i32 = (SCREEN_W - (9  * KEY_W + 8 * KEY_GAP)) / 2;
pub const ROW2_X: i32 = (SCREEN_W - (7  * KEY_W + 6 * KEY_GAP)) / 2;

pub const ROW0_Y: i32 = KB_Y;
pub const ROW1_Y: i32 = KB_Y + ROW_STEP;
pub const ROW2_Y: i32 = KB_Y + 2 * ROW_STEP;
pub const ROW3_Y: i32 = KB_Y + 3 * ROW_STEP;

pub const SPACE_X: i32 = 200;
pub const SPACE_W: i32 = 280;
pub const BKSP_X: i32  = 510;
pub const BKSP_W: i32  = 250;

// EnterPassphrase action buttons
pub const PP_BTN_Y: i32     = 390;
pub const PP_BTN_H: i32     = 50;
pub const PP_BTN_W: i32     = 180;
pub const PP_SKIP_X: i32    = 40;
pub const PP_CONFIRM_X: i32 = SCREEN_W - 40 - PP_BTN_W;

// PIN numpad (2 rows of 5 keys)
pub const PIN_KEY_W: i32    = 100;
pub const PIN_KEY_H: i32    = 80;
pub const PIN_KEY_GAP: i32  = 20;
pub const PIN_KEY_STEP: i32 = PIN_KEY_W + PIN_KEY_GAP;
pub const PIN_ROW_X: i32    = (SCREEN_W - (5 * PIN_KEY_W + 4 * PIN_KEY_GAP)) / 2;
pub const PIN_ROW0_Y: i32   = 140;
pub const PIN_ROW1_Y: i32   = PIN_ROW0_Y + PIN_KEY_H + PIN_KEY_GAP;
pub const PIN_DEL_X: i32    = 40;
pub const PIN_DEL_W: i32    = 200;
pub const PIN_DEL_Y: i32    = 360;
pub const PIN_DEL_H: i32    = 50;

// PIN dots
pub const DOT_SIZE: i32 = 20;
pub const DOT_GAP: i32  = 20;
pub const DOTS_X: i32   = (SCREEN_W - (6 * DOT_SIZE + 5 * DOT_GAP)) / 2;
pub const DOTS_Y: i32   = 70;

// Sign flow
pub const SIGN_VF_W: i32 = 400;
pub const SIGN_VF_H: i32 = 300;
pub const SIGN_VF_X: i32 = (SCREEN_W - SIGN_VF_W) / 2;
pub const SIGN_VF_Y: i32 = 70;

// Receive screen
pub const QR_SIZE: i32 = 240;
pub const QR_X: i32    = (SCREEN_W - QR_SIZE) / 2;
pub const QR_Y: i32    = 110;

// Settings screen
pub const SETTINGS_BTN_W: i32 = 360;
pub const SETTINGS_BTN_H: i32 = 60;
pub const SETTINGS_BTN_X: i32 = (SCREEN_W - SETTINGS_BTN_W) / 2;
pub const SETTINGS_Y0: i32    = 120;
pub const SETTINGS_Y1: i32    = 210;
pub const SETTINGS_Y2: i32    = 300;

// RestoreWallet input + suggestion strip (sits above the QWERTY keyboard at KB_Y=115)
pub const RESTORE_PROGRESS_Y: i32 = 45;
pub const RESTORE_INPUT_Y: i32    = 65;
pub const RESTORE_SUGGEST_Y: i32  = 78;
pub const RESTORE_SUGGEST_H: i32  = 37;  // exactly fills Y=78..115 = KB_Y
pub const RESTORE_SUGGEST_W: i32  = 200;
pub const RESTORE_SUGGEST_GAP: i32 = 20;
pub const RESTORE_SUGGEST_X0: i32 =
    (SCREEN_W - 3 * RESTORE_SUGGEST_W - 2 * RESTORE_SUGGEST_GAP) / 2; // 80
pub const RESTORE_SUGGEST_X1: i32 = RESTORE_SUGGEST_X0 + RESTORE_SUGGEST_W + RESTORE_SUGGEST_GAP; // 300
pub const RESTORE_SUGGEST_X2: i32 = RESTORE_SUGGEST_X1 + RESTORE_SUGGEST_W + RESTORE_SUGGEST_GAP; // 520

// Home grid (2x2)
pub const HOME_BTN_W: i32 = 300;
pub const HOME_BTN_H: i32 = 140;
pub const HOME_GAP: i32   = 40;
pub const HOME_X0: i32    = (SCREEN_W - (2 * HOME_BTN_W + HOME_GAP)) / 2;
pub const HOME_X1: i32    = HOME_X0 + HOME_BTN_W + HOME_GAP;
pub const HOME_Y0: i32    = (SCREEN_H - (2 * HOME_BTN_H + HOME_GAP)) / 2;
pub const HOME_Y1: i32    = HOME_Y0 + HOME_BTN_H + HOME_GAP;
