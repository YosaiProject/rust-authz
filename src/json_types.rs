#[cfg(feature="serde_derive")]
include!("json_types.rs.in");

#[cfg(not(feature="serde_derive"))]
include!(concat!(env!("OUT_DIR"), "/json_types.rs"));
