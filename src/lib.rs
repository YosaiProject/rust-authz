#![cfg_attr(feature="serde_derive", feature(proc_macro))]

#[cfg(feature = "serde_derive")]
#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

pub mod json_types;
pub mod authz;
pub use authz::_is_permitted_from_str;
pub use authz::_is_permitted_from_perm;
