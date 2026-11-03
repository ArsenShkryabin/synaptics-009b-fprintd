//! Sensor register map (SCM/RCM/AFE) for the Prometheus sensor's memory-mapped
//! `0x8000_xxxx` register block, accessed via `write_hw_reg32` / `read_hw_reg32`.
//!
//! Ported verbatim from the DLL's register-name table
//! `g_scm_register_name_table@0x18013d478` (baseline `synaWudfBioUsb.dll`), the
//! canonical sequential map (`0x80002000..=0x80002400` + RAM + RCM clocks).
//!
//! NOTE: a *second*, older alias table precedes this one in the DLL (entries 0-21,
//! `SCM_PGA_AGC_RIGHT/LEFT_*` naming) whose gain addresses (`0x80002078`/`0x80002150`)
//! do NOT map on the `0x0199` silicon (`0x80002078` is [`ScmReg::ScmCf3ClkCtrl`]
//! here, reads 0). Use THIS table. `AI0`/`AI1` = the two analog islands (zones);
//! `RIGHT`≈`AI0`, `LEFT`≈`AI1`. See docs/capture/009a-calibration-port.md.

/// A named sensor control-map register; the discriminant is its `0x8000_xxxx` address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ScmReg {
    /// `RCM_ADC_DELAY`
    RcmAdcDelay = 0x80002000,
    /// `SCM_SEN_CTRL`
    ScmSenCtrl = 0x80002004,
    /// `SCM_GETPRINT_COUNT`
    ScmGetprintCount = 0x80002008,
    /// `CURRENT_COUNT`
    CurrentCount = 0x8000200c,
    /// `CURRENT_FRAME`
    CurrentFrame = 0x80002010,
    /// `CURRENT_LINE`
    CurrentLine = 0x80002014,
    /// `SCM_SEN_STATUS`
    ScmSenStatus = 0x80002018,
    /// `SCM_INT_EN`
    ScmIntEn = 0x8000201c,
    /// `SCM_INT_LINE_COUNT`
    ScmIntLineCount = 0x80002020,
    /// `SCM_ADC_CTRL`
    ScmAdcCtrl = 0x80002024,
    /// `SCM_ADC_FW_CTRL`
    ScmAdcFwCtrl = 0x80002028,
    /// `SCM_AFE_MASTER_CFG`
    ScmAfeMasterCfg = 0x8000202c,
    /// `SCM_AFE_LNA2`
    ScmAfeLna2 = 0x80002030,
    /// `SCM_AFE_VGA`
    ScmAfeVga = 0x80002034,
    /// `SCM_AFE_LPF`
    ScmAfeLpf = 0x80002038,
    /// `SCM_AFE_LPF_VGA`
    ScmAfeLpfVga = 0x8000203c,
    /// `SCM_AFE_RMS`
    ScmAfeRms = 0x80002040,
    /// `SCM_AFE_CARR`
    ScmAfeCarr = 0x80002044,
    /// `SCM_AFE_PDET_CTRL`
    ScmAfePdetCtrl = 0x80002048,
    /// `SCM_AFE_PDET_GAIN`
    ScmAfePdetGain = 0x8000204c,
    /// `SCM_AFE_LIA`
    ScmAfeLia = 0x80002050,
    /// `SCM_AFE_POWER1`
    ScmAfePower1 = 0x80002054,
    /// `SCM_AFE_POWER2`
    ScmAfePower2 = 0x80002058,
    /// `SCM_CAL_CFG`
    ScmCalCfg = 0x8000205c,
    /// `SCM_ANALOG_TEST`
    ScmAnalogTest = 0x80002060,
    /// `SCM_SO_CTRL`
    ScmSoCtrl = 0x80002064,
    /// `SCM_CLK_CTRL`
    ScmClkCtrl = 0x8000206c,
    /// `SCM_CF1_CLK_CTRL`
    ScmCf1ClkCtrl = 0x80002070,
    /// `SCM_CF2_CLK_CTRL`
    ScmCf2ClkCtrl = 0x80002074,
    /// `SCM_CF3_CLK_CTRL`
    ScmCf3ClkCtrl = 0x80002078,
    /// `SCM_CF4_CLK_CTRL`
    ScmCf4ClkCtrl = 0x8000207c,
    /// `SCM_SPARE`
    ScmSpare = 0x80002080,
    /// `SCM_LAYER_ID`
    ScmLayerId = 0x80002084,
    /// `SCM_WOVAR_CTRL`
    ScmWovarCtrl = 0x80002088,
    /// `SCM_WOVAR_STATUS`
    ScmWovarStatus = 0x8000208c,
    /// `SCM_WOVAR_FD_THRESH`
    ScmWovarFdThresh = 0x80002090,
    /// `SCM_WOVAR_FU_THRESH`
    ScmWovarFuThresh = 0x80002094,
    /// `SCM_ASP_CTRL`
    ScmAspCtrl = 0x80002098,
    /// `SCM_ASP_STATUS`
    ScmAspStatus = 0x8000209c,
    /// `SCM_ASP_FD_THRESH`
    ScmAspFdThresh = 0x800020a0,
    /// `SCM_ASP_FU_THRESH`
    ScmAspFuThresh = 0x800020a4,
    /// `SCM_WOF_CTRL1`
    ScmWofCtrl1 = 0x800020a8,
    /// `SCM_WOF_CTRL2`
    ScmWofCtrl2 = 0x800020ac,
    /// `SCM_WOF_STATUS`
    ScmWofStatus = 0x800020b0,
    /// `SCM_WOF_THRESH`
    ScmWofThresh = 0x800020b4,
    /// `SCM_BASELINE_CTRL`
    ScmBaselineCtrl = 0x800020b8,
    /// `SCM_HP_CTRL`
    ScmHpCtrl = 0x800020bc,
    /// `SCM_HP_LINE_CNT_LONG`
    ScmHpLineCntLong = 0x800020c0,
    /// `SCM_HP_LINE_CNT_SHORT`
    ScmHpLineCntShort = 0x800020c4,
    /// `SCM_HP_LONG_VALUE`
    ScmHpLongValue = 0x800020c8,
    /// `SCM_HP_SHORT_VALUE`
    ScmHpShortValue = 0x800020cc,
    /// `SCM_HP_AI0_D_A`
    ScmHpAi0DA = 0x800020d0,
    /// `SCM_HP_AI1_D_A`
    ScmHpAi1DA = 0x800020d4,
    /// `SCM_HP_AI0_SUM`
    ScmHpAi0Sum = 0x800020d8,
    /// `SCM_HP_AI1_SUM`
    ScmHpAi1Sum = 0x800020dc,
    /// `SCM_HP_AI0_LONG_THRESH`
    ScmHpAi0LongThresh = 0x800020e0,
    /// `SCM_HP_AI1_LONG_THRESH`
    ScmHpAi1LongThresh = 0x800020e4,
    /// `SCM_HP_AI0_SHORT_THRESH`
    ScmHpAi0ShortThresh = 0x800020e8,
    /// `SCM_HP_AI1_SHORT_THRESH`
    ScmHpAi1ShortThresh = 0x800020ec,
    /// `SCM_HP_SAFETY_AI0_SUM`
    ScmHpSafetyAi0Sum = 0x800020f0,
    /// `SCM_HP_SAFETY_AI0_THRESH`
    ScmHpSafetyAi0Thresh = 0x800020f4,
    /// `SCM_HP_SAFETY_AI1_SUM`
    ScmHpSafetyAi1Sum = 0x800020f8,
    /// `SCM_HP_SAFETY_AI1_THRESH`
    ScmHpSafetyAi1Thresh = 0x800020fc,
    /// `SCM_HP_ADDER`
    ScmHpAdder = 0x80002100,
    /// `SCM_VGA_AGC_CTRL`
    ScmVgaAgcCtrl = 0x80002104,
    /// `SCM_VGA_AGC_INTERVAL`
    ScmVgaAgcInterval = 0x80002108,
    /// `SCM_VGA_AGC_AI0_GAIN`
    ScmVgaAgcAi0Gain = 0x8000210c,
    /// `SCM_VGA_AGC_AI1_GAIN`
    ScmVgaAgcAi1Gain = 0x80002110,
    /// `SCM_VGA_AGC_AI0_RED_STATUS`
    ScmVgaAgcAi0RedStatus = 0x80002114,
    /// `SCM_VGA_AGC_AI0_YELLOW_STATUS`
    ScmVgaAgcAi0YellowStatus = 0x80002118,
    /// `SCM_VGA_AGC_AI1_RED_STATUS`
    ScmVgaAgcAi1RedStatus = 0x8000211c,
    /// `SCM_VGA_AGC_AI1_YELLOW_STATUS`
    ScmVgaAgcAi1YellowStatus = 0x80002120,
    /// `SCM_VGA_AGC_AI0_RED_THRESH_CNT`
    ScmVgaAgcAi0RedThreshCnt = 0x80002124,
    /// `SCM_VGA_AGC_AI0_YELLOW_THRESH_CNT`
    ScmVgaAgcAi0YellowThreshCnt = 0x80002128,
    /// `SCM_VGA_AGC_AI1_RED_THRESH_CNT`
    ScmVgaAgcAi1RedThreshCnt = 0x8000212c,
    /// `SCM_VGA_AGC_AI1_YELLOW_THRESH_CNT`
    ScmVgaAgcAi1YellowThreshCnt = 0x80002130,
    /// `SCM_VGA_AGC_AI0_THRESH_VAL`
    ScmVgaAgcAi0ThreshVal = 0x80002134,
    /// `SCM_VGA_AGC_AI1_THRESH_VAL`
    ScmVgaAgcAi1ThreshVal = 0x80002138,
    /// `SCM_VGA_AGC_AI0_STEP`
    ScmVgaAgcAi0Step = 0x8000213c,
    /// `SCM_VGA_AGC_AI1_STEP`
    ScmVgaAgcAi1Step = 0x80002140,
    /// `SCM_PGA_AGC_CTRL`
    ScmPgaAgcCtrl = 0x80002144,
    /// `SCM_PGA_AGC_INTERVAL`
    ScmPgaAgcInterval = 0x80002148,
    /// `SCM_PGA_AGC_AI0_GAIN`
    ScmPgaAgcAi0Gain = 0x8000214c,
    /// `SCM_PGA_AGC_AI1_GAIN`
    ScmPgaAgcAi1Gain = 0x80002150,
    /// `SCM_PGA_AGC_AI0_STATUS`
    ScmPgaAgcAi0Status = 0x80002154,
    /// `SCM_PGA_AGC_AI1_STATUS`
    ScmPgaAgcAi1Status = 0x80002158,
    /// `SCM_PGA_AGC_AI0_THRESH_CNT`
    ScmPgaAgcAi0ThreshCnt = 0x8000215c,
    /// `SCM_PGA_AGC_AI1_THRESH_CNT`
    ScmPgaAgcAi1ThreshCnt = 0x80002160,
    /// `SCM_PGA_AGC_AI0_THRESH_VAL`
    ScmPgaAgcAi0ThreshVal = 0x80002164,
    /// `SCM_PGA_AGC_AI1_THRESH_VAL`
    ScmPgaAgcAi1ThreshVal = 0x80002168,
    /// `SCM_PGA_AGC_AI0_STEP`
    ScmPgaAgcAi0Step = 0x8000216c,
    /// `SCM_PGA_AGC_AI1_STEP`
    ScmPgaAgcAi1Step = 0x800023fc,
    /// `SCM_TIMESLOT_OFFSET`
    ScmTimeslotOffset = 0x80002400,
    /// `SCM_RAM`
    ScmRam = 0x80002800,
    /// `RCM_PIX_CLK`
    RcmPixClk = 0x80002808,
    /// `RCM_CPU_CLK_SEL`
    RcmCpuClkSel = 0x80002814,
    /// `RCM_SO_REF_CLK`
    RcmSoRefClk = 0x8000281c,
}

impl ScmReg {
    /// The register's memory-mapped address (`0x8000_xxxx`).
    #[inline]
    pub const fn addr(self) -> u32 {
        self as u32
    }

    /// The register's canonical DLL name (`SCM_*` / `RCM_*`).
    pub const fn scm_name(self) -> &'static str {
        match self {
            ScmReg::RcmAdcDelay => "RCM_ADC_DELAY",
            ScmReg::ScmSenCtrl => "SCM_SEN_CTRL",
            ScmReg::ScmGetprintCount => "SCM_GETPRINT_COUNT",
            ScmReg::CurrentCount => "CURRENT_COUNT",
            ScmReg::CurrentFrame => "CURRENT_FRAME",
            ScmReg::CurrentLine => "CURRENT_LINE",
            ScmReg::ScmSenStatus => "SCM_SEN_STATUS",
            ScmReg::ScmIntEn => "SCM_INT_EN",
            ScmReg::ScmIntLineCount => "SCM_INT_LINE_COUNT",
            ScmReg::ScmAdcCtrl => "SCM_ADC_CTRL",
            ScmReg::ScmAdcFwCtrl => "SCM_ADC_FW_CTRL",
            ScmReg::ScmAfeMasterCfg => "SCM_AFE_MASTER_CFG",
            ScmReg::ScmAfeLna2 => "SCM_AFE_LNA2",
            ScmReg::ScmAfeVga => "SCM_AFE_VGA",
            ScmReg::ScmAfeLpf => "SCM_AFE_LPF",
            ScmReg::ScmAfeLpfVga => "SCM_AFE_LPF_VGA",
            ScmReg::ScmAfeRms => "SCM_AFE_RMS",
            ScmReg::ScmAfeCarr => "SCM_AFE_CARR",
            ScmReg::ScmAfePdetCtrl => "SCM_AFE_PDET_CTRL",
            ScmReg::ScmAfePdetGain => "SCM_AFE_PDET_GAIN",
            ScmReg::ScmAfeLia => "SCM_AFE_LIA",
            ScmReg::ScmAfePower1 => "SCM_AFE_POWER1",
            ScmReg::ScmAfePower2 => "SCM_AFE_POWER2",
            ScmReg::ScmCalCfg => "SCM_CAL_CFG",
            ScmReg::ScmAnalogTest => "SCM_ANALOG_TEST",
            ScmReg::ScmSoCtrl => "SCM_SO_CTRL",
            ScmReg::ScmClkCtrl => "SCM_CLK_CTRL",
            ScmReg::ScmCf1ClkCtrl => "SCM_CF1_CLK_CTRL",
            ScmReg::ScmCf2ClkCtrl => "SCM_CF2_CLK_CTRL",
            ScmReg::ScmCf3ClkCtrl => "SCM_CF3_CLK_CTRL",
            ScmReg::ScmCf4ClkCtrl => "SCM_CF4_CLK_CTRL",
            ScmReg::ScmSpare => "SCM_SPARE",
            ScmReg::ScmLayerId => "SCM_LAYER_ID",
            ScmReg::ScmWovarCtrl => "SCM_WOVAR_CTRL",
            ScmReg::ScmWovarStatus => "SCM_WOVAR_STATUS",
            ScmReg::ScmWovarFdThresh => "SCM_WOVAR_FD_THRESH",
            ScmReg::ScmWovarFuThresh => "SCM_WOVAR_FU_THRESH",
            ScmReg::ScmAspCtrl => "SCM_ASP_CTRL",
            ScmReg::ScmAspStatus => "SCM_ASP_STATUS",
            ScmReg::ScmAspFdThresh => "SCM_ASP_FD_THRESH",
            ScmReg::ScmAspFuThresh => "SCM_ASP_FU_THRESH",
            ScmReg::ScmWofCtrl1 => "SCM_WOF_CTRL1",
            ScmReg::ScmWofCtrl2 => "SCM_WOF_CTRL2",
            ScmReg::ScmWofStatus => "SCM_WOF_STATUS",
            ScmReg::ScmWofThresh => "SCM_WOF_THRESH",
            ScmReg::ScmBaselineCtrl => "SCM_BASELINE_CTRL",
            ScmReg::ScmHpCtrl => "SCM_HP_CTRL",
            ScmReg::ScmHpLineCntLong => "SCM_HP_LINE_CNT_LONG",
            ScmReg::ScmHpLineCntShort => "SCM_HP_LINE_CNT_SHORT",
            ScmReg::ScmHpLongValue => "SCM_HP_LONG_VALUE",
            ScmReg::ScmHpShortValue => "SCM_HP_SHORT_VALUE",
            ScmReg::ScmHpAi0DA => "SCM_HP_AI0_D_A",
            ScmReg::ScmHpAi1DA => "SCM_HP_AI1_D_A",
            ScmReg::ScmHpAi0Sum => "SCM_HP_AI0_SUM",
            ScmReg::ScmHpAi1Sum => "SCM_HP_AI1_SUM",
            ScmReg::ScmHpAi0LongThresh => "SCM_HP_AI0_LONG_THRESH",
            ScmReg::ScmHpAi1LongThresh => "SCM_HP_AI1_LONG_THRESH",
            ScmReg::ScmHpAi0ShortThresh => "SCM_HP_AI0_SHORT_THRESH",
            ScmReg::ScmHpAi1ShortThresh => "SCM_HP_AI1_SHORT_THRESH",
            ScmReg::ScmHpSafetyAi0Sum => "SCM_HP_SAFETY_AI0_SUM",
            ScmReg::ScmHpSafetyAi0Thresh => "SCM_HP_SAFETY_AI0_THRESH",
            ScmReg::ScmHpSafetyAi1Sum => "SCM_HP_SAFETY_AI1_SUM",
            ScmReg::ScmHpSafetyAi1Thresh => "SCM_HP_SAFETY_AI1_THRESH",
            ScmReg::ScmHpAdder => "SCM_HP_ADDER",
            ScmReg::ScmVgaAgcCtrl => "SCM_VGA_AGC_CTRL",
            ScmReg::ScmVgaAgcInterval => "SCM_VGA_AGC_INTERVAL",
            ScmReg::ScmVgaAgcAi0Gain => "SCM_VGA_AGC_AI0_GAIN",
            ScmReg::ScmVgaAgcAi1Gain => "SCM_VGA_AGC_AI1_GAIN",
            ScmReg::ScmVgaAgcAi0RedStatus => "SCM_VGA_AGC_AI0_RED_STATUS",
            ScmReg::ScmVgaAgcAi0YellowStatus => "SCM_VGA_AGC_AI0_YELLOW_STATUS",
            ScmReg::ScmVgaAgcAi1RedStatus => "SCM_VGA_AGC_AI1_RED_STATUS",
            ScmReg::ScmVgaAgcAi1YellowStatus => "SCM_VGA_AGC_AI1_YELLOW_STATUS",
            ScmReg::ScmVgaAgcAi0RedThreshCnt => "SCM_VGA_AGC_AI0_RED_THRESH_CNT",
            ScmReg::ScmVgaAgcAi0YellowThreshCnt => "SCM_VGA_AGC_AI0_YELLOW_THRESH_CNT",
            ScmReg::ScmVgaAgcAi1RedThreshCnt => "SCM_VGA_AGC_AI1_RED_THRESH_CNT",
            ScmReg::ScmVgaAgcAi1YellowThreshCnt => "SCM_VGA_AGC_AI1_YELLOW_THRESH_CNT",
            ScmReg::ScmVgaAgcAi0ThreshVal => "SCM_VGA_AGC_AI0_THRESH_VAL",
            ScmReg::ScmVgaAgcAi1ThreshVal => "SCM_VGA_AGC_AI1_THRESH_VAL",
            ScmReg::ScmVgaAgcAi0Step => "SCM_VGA_AGC_AI0_STEP",
            ScmReg::ScmVgaAgcAi1Step => "SCM_VGA_AGC_AI1_STEP",
            ScmReg::ScmPgaAgcCtrl => "SCM_PGA_AGC_CTRL",
            ScmReg::ScmPgaAgcInterval => "SCM_PGA_AGC_INTERVAL",
            ScmReg::ScmPgaAgcAi0Gain => "SCM_PGA_AGC_AI0_GAIN",
            ScmReg::ScmPgaAgcAi1Gain => "SCM_PGA_AGC_AI1_GAIN",
            ScmReg::ScmPgaAgcAi0Status => "SCM_PGA_AGC_AI0_STATUS",
            ScmReg::ScmPgaAgcAi1Status => "SCM_PGA_AGC_AI1_STATUS",
            ScmReg::ScmPgaAgcAi0ThreshCnt => "SCM_PGA_AGC_AI0_THRESH_CNT",
            ScmReg::ScmPgaAgcAi1ThreshCnt => "SCM_PGA_AGC_AI1_THRESH_CNT",
            ScmReg::ScmPgaAgcAi0ThreshVal => "SCM_PGA_AGC_AI0_THRESH_VAL",
            ScmReg::ScmPgaAgcAi1ThreshVal => "SCM_PGA_AGC_AI1_THRESH_VAL",
            ScmReg::ScmPgaAgcAi0Step => "SCM_PGA_AGC_AI0_STEP",
            ScmReg::ScmPgaAgcAi1Step => "SCM_PGA_AGC_AI1_STEP",
            ScmReg::ScmTimeslotOffset => "SCM_TIMESLOT_OFFSET",
            ScmReg::ScmRam => "SCM_RAM",
            ScmReg::RcmPixClk => "RCM_PIX_CLK",
            ScmReg::RcmCpuClkSel => "RCM_CPU_CLK_SEL",
            ScmReg::RcmSoRefClk => "RCM_SO_REF_CLK",
        }
    }
}
