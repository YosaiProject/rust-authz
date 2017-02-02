#![feature(test)]

extern crate authz;

#[macro_use]
extern crate bencher;

extern crate test;
use test::Bencher;

fn test_perm() {
    let required_perm = "domain1:action4:target4";
    let assigned_perms: Vec<&str> = vec!("domain1:action1", "domain1:action2", "domain1:action4");
    let _ = authz::_is_permitted_from_str(&required_perm, assigned_perms);
}

#[bench]
fn test_is_permitted_from_str(b: &mut Bencher)  {
    b.iter(|| test_perm())
}
