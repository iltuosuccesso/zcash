use memuse::DynamicUsage;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    local_consensus::{self, LocalNetwork},
};

/// Chain parameters for the networks supported by `zcashd`.
///
/// Tcoin: mainnet and testnet are new chains whose network upgrades activate at
/// heights chosen in `chainparams.cpp`, so they cannot use the Zcash constants in
/// `consensus::Network`. They are represented as `Tcoin`, which takes the
/// activation heights from C++ like regtest does, but keeps the mainnet or
/// testnet network type so that addresses are encoded for the right network.
#[derive(Clone, Copy)]
pub(crate) enum Network {
    Tcoin(consensus::NetworkType, local_consensus::LocalNetwork),
    RegTest(local_consensus::LocalNetwork),
}

impl DynamicUsage for Network {
    fn dynamic_usage(&self) -> usize {
        match self {
            // We know that `Option<BlockHeight>` allocates no memory.
            Network::Tcoin { .. } | Network::RegTest { .. } => 0,
        }
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        match self {
            // We know that `Option<BlockHeight>` allocates no memory.
            Network::Tcoin { .. } | Network::RegTest { .. } => (0, Some(0)),
        }
    }
}

/// Constructs a `Network` from the given network string.
///
/// The heights are used for every network: Tcoin sets its own activation heights
/// on mainnet and testnet too.
#[allow(clippy::too_many_arguments)]
pub(crate) fn network(
    network: &str,
    overwinter: i32,
    sapling: i32,
    blossom: i32,
    heartwood: i32,
    canopy: i32,
    nu5: i32,
    nu6: i32,
    nu6_1: i32,
    nu6_2: i32,
) -> Result<Box<Network>, &'static str> {
    let i32_to_optional_height = |n: i32| {
        if n.is_negative() {
            None
        } else {
            Some(BlockHeight::from_u32(n.unsigned_abs()))
        }
    };

    let heights = LocalNetwork {
        overwinter: i32_to_optional_height(overwinter),
        sapling: i32_to_optional_height(sapling),
        blossom: i32_to_optional_height(blossom),
        heartwood: i32_to_optional_height(heartwood),
        canopy: i32_to_optional_height(canopy),
        nu5: i32_to_optional_height(nu5),
        nu6: i32_to_optional_height(nu6),
        nu6_1: i32_to_optional_height(nu6_1),
        nu6_2: i32_to_optional_height(nu6_2),
    };

    let params = match network {
        "main" => Network::Tcoin(consensus::NetworkType::Main, heights),
        "test" => Network::Tcoin(consensus::NetworkType::Test, heights),
        "regtest" => Network::RegTest(heights),
        _ => return Err("Unsupported network kind"),
    };

    Ok(Box::new(params))
}

impl consensus::Parameters for Network {
    fn network_type(&self) -> consensus::NetworkType {
        match self {
            Self::Tcoin(network_type, _) => *network_type,
            Self::RegTest(params) => params.network_type(),
        }
    }

    fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<consensus::BlockHeight> {
        match self {
            Self::Tcoin(_, heights) => heights.activation_height(nu),
            Self::RegTest(params) => params.activation_height(nu),
        }
    }
}
