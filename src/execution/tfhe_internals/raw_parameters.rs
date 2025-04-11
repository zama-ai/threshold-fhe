// NOTE: In the near future we want to import those directly from tfhe-rs !!
// All these come from Nigel's script in NIST Paper for pfail 2^-128

// Main Document Parameters
// Parameters When Main Ciphertexts are LWE
use tfhe::{
    boolean::prelude::*,
    shortint::{
        parameters::{
            CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
            ShortintKeySwitchingParameters, SupportedCompactPkeZkScheme,
        },
        prelude::*,
    },
};

// p-fail = 2^-128.788
pub const NIST_PARAM_1_CARRY_1_COMPACT_PK_PBS_KS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(928),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(7),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.788,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: None,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(1024),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
};

// Parameters to keyswitch from input PKE 1_1 TUniform parameters to 1_1 PBS_KS compute parameters
// arriving under the big key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_PBS_KS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(7),
    destination_key: EncryptionKeyChoice::Small,
};

// **********************************

// p-fail = 2^-128.788
pub const NIST_PARAM_2_CARRY_2_COMPACT_PK_PBS_KS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1006),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.788,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Small,
        modulus_switch_noise_reduction_params: None,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(1024),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
};

// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 PBS_KS compute parameters
// arriving under the big key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_PBS_KS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(6),
    destination_key: EncryptionKeyChoice::Small,
};

// Parameters When Main Ciphertexts are FGLWE

// p-fail = 2^-128.788
pub const NIST_PARAM_1_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(848),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(16),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -128.788,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: None,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(1024),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
};

// Parameters to keyswitch from input PKE 1_1 TUniform parameters to 1_1 KS_PBS compute parameters
// arriving under the big key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(14),
    destination_key: EncryptionKeyChoice::Big,
};

// **********************************

// p-fail = 2^-128.788
pub const NIST_PARAM_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(928),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(0),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.788,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: None,
    };

// Parameters for the PKE operation
pub const NIST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    CompactPublicKeyEncryptionParameters = CompactPublicKeyEncryptionParameters {
    encryption_lwe_dimension: LweDimension(1024),
    encryption_noise_distribution: DynamicDistribution::new_t_uniform(42),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    expansion_kind: CompactCiphertextListExpansionKind::RequiresCasting,
    zk_scheme: SupportedCompactPkeZkScheme::V1,
};

// Parameters to keyswitch from input PKE 2_2 TUniform parameters to 2_2 KS_PBS compute parameters
// arriving under the big key
pub const NIST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters = ShortintKeySwitchingParameters {
    ks_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(17),
    destination_key: EncryptionKeyChoice::Big,
};

// **********************************
