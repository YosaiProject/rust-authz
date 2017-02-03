#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

pub mod authz;
pub use authz::{is_permitted_from_str, is_permitted_from_perm, perms_from_buffer, Permission};
