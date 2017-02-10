#![feature(test)]

extern crate authz;
extern crate serde_json;

#[macro_use]
extern crate bencher;

extern crate test;
use test::Bencher;

fn test_permitted_from_string() {
    let required_perm = "domain1:action4:target4";
    let assigned_perms: Vec<&str> = vec!("domain1:action1", "domain1:action2", "domain1:action4");
    let _ = authz::is_permitted_from_str(&required_perm, assigned_perms);
}

fn test_permitted_from_json(required: &str, serialized: String) {
    let deserialized: Vec<authz::Permission> = authz::perms_from_buffer(serialized.as_bytes()).unwrap();
    let _ = authz::is_permitted_from_perm(&required, deserialized);
}

#[bench]
fn test_is_permitted_from_string(b: &mut Bencher)  {
    b.iter(|| test_permitted_from_string())
}

#[bench]
fn test_is_permitted_from_json(b: &mut Bencher)  {
    let required =  "domain2:action4:target7";
    let permissions: Vec<authz::Permission> = vec![authz::Permission::new("domain1:action1"),
                                                   authz::Permission::new("domain2:action3,action4")];
    b.iter(|| test_permitted_from_json(required, serde_json::to_string(&permissions).unwrap()))
}
