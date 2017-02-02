extern crate serde_json;

use json_types::Permission;
use std::slice;
use std::ffi::CStr;
use std::panic;
use std::str;
use libc::{size_t, c_char, c_int};
use std::collections::HashSet;
use std::hash::BuildHasherDefault;
use seahash::SeaHasher;

type SeaHashSet<K> = HashSet<K, BuildHasherDefault<SeaHasher>>;

static PART_DELIMETER: &'static str = ":";
static SUBPART_DELIMETER: &'static str = ",";


impl<'a> Permission {
    pub fn new(wildcard_perm: &str) -> Permission {
        let (domain, actions, targets) = Permission::init_parts(wildcard_perm);
        let perm = Permission {
            domain: domain,
            actions: actions,
            targets: targets,
        };
        perm
    }

    fn part_from_str(s: Option<&str>) -> SeaHashSet<String> {
        match s {
            Some("") | None => {
                let mut set = SeaHashSet::default();
                set.insert(String::from("*"));
                set
            }
            Some(s) => {
                let mut set = SeaHashSet::default();
                for rule in s.split(SUBPART_DELIMETER).map(str::trim) {
                    set.insert(String::from(rule));
                }
                set
            }
        }
    }

    fn init_parts(wildcard_perm: &'a str) -> (String, SeaHashSet<String>, SeaHashSet<String>) {
        let mut iter = wildcard_perm.split(PART_DELIMETER).map(str::trim);

        let domain = match iter.next() {
            Some("") | Some("*") | None => String::from("*"),
            Some(domain) => String::from(domain),
        };
        let actions = Permission::part_from_str(iter.next());
        let targets = Permission::part_from_str(iter.next());

        (domain, actions, targets)
    }

    pub fn implies_from_str(&self, wildcard_permission: &str) -> bool {
        let permission = Permission::new(wildcard_permission);
        self.implies_from_perm(&permission)
    }

    pub fn implies_from_perm(&self, permission: &Permission) -> bool {
        if self.domain != "*" {
            if self.domain != permission.domain {
                return false;
            }
        }

        if !self.actions.contains("*") {
            if !&self.actions.is_superset(&permission.actions) {
                return false;
            }
        }

        if !self.targets.contains("*") {
            if !&self.targets.is_superset(&permission.targets) {
                return false;
            }
        }
        return true;
    }
}

pub fn _is_permitted_from_str<'a, I>(required_perm: &str, assigned_perms: I) -> i32
    where I: IntoIterator<Item = &'a str>
{
    let required_permission = Permission::new(&required_perm);

    for assigned in assigned_perms {
        let assigned_permission = Permission::new(assigned);
        if assigned_permission.implies_from_perm(&required_permission) {
            return 1;
        }
    }
    return 0;
}

pub fn _is_permitted_from_perm(required_perm: &str, assigned_perms: Vec<Permission>) -> i32 {
    let required_permission = Permission::new(required_perm);

    for assigned in assigned_perms {
        if assigned.implies_from_perm(&required_permission) {
            return 1;
        }
    }
    return 0;
}




#[cfg(test)]
mod test {
    use authz::{Permission, _is_permitted_from_str, _is_permitted_from_perm};
    use std::collections::HashSet;
    use std::hash::BuildHasherDefault;
    use seahash::SeaHasher;

    type SeaHashSet<K> = HashSet<K, BuildHasherDefault<SeaHasher>>;

    #[test]
    fn test_new_permission() {

        struct Perm<'a> {
            wildcard_perm: &'a str,
            domain: &'a str,
            actions: Vec<&'a str>,
            targets: Vec<&'a str>,
        }

        let tests = [Perm { wildcard_perm: "", domain: "*", actions: vec!["*"], targets: vec!["*"],},
                     Perm { wildcard_perm: "domain1", domain: "domain1", actions: vec!["*"], targets: vec!["*"],},
                     Perm { wildcard_perm: "domain1:action1", domain: "domain1", actions: vec!["action1"], targets: vec!["*"], },
                     Perm { wildcard_perm: ":action1, action2, action3", domain: "*", actions: vec!["action1", "action2", "action3"], targets: vec!["*"],},
                     Perm { wildcard_perm: "domain1:action1, action2:target1, target2", domain: "domain1", actions: vec!["action1", "action2"], targets: vec!["target1", "target2"], }];

        for test in tests.iter() {
            let perm: Permission = Permission::new(test.wildcard_perm);

            let expected_actions: SeaHashSet<String> =
                test.actions.iter().map(|x| x.to_string()).collect();
            let expected_targets: SeaHashSet<String> =
                test.targets.iter().map(|x| x.to_string()).collect();

            assert_eq!(perm.domain == test.domain, true);
            assert_eq!(perm.actions == expected_actions, true);
            assert_eq!(perm.targets == expected_targets, true);
        }
    }

    #[test]
    fn test_part_from_str() {
        let tests = vec![(Some(""), vec!["*"]),
                         (None, vec!["*"]),
                         (Some("action1, action2, action3"), vec!["action1", "action2", "action3"]),
                         (Some("incorrect format"), vec!["incorrect format"])];
        for &(ref input, ref expected) in tests.iter(){
            let expected_result: SeaHashSet<String> = expected.iter().map(|x| x.to_string()).collect();
            let result: SeaHashSet<String> = Permission::part_from_str(*input);
            assert_eq!(result, expected_result);
        }
    }

    #[test]
    fn test_implies_from_str() {
        let perm = Permission::new("domain1:action1");
        assert_eq!(perm.implies_from_str("domain1:action1:target1"), true);
        assert_eq!(perm.implies_from_str("domain1:action2"), false);
    }

    #[test]
    fn test_implies_from_perm() {
        let perm1: Permission = Permission::new("domain1:action1");
        let perm2: Permission = Permission::new("domain1:action1,action2");
        let perm3: Permission = Permission::new("domain1:action1,action2:target1");
        let perm4: Permission = Permission::new("domain1:action3,action4:target2,target3");
        let perm5: Permission = Permission::new("domain1:action1,action2,action3,action4");
        let perm6: Permission = Permission::new(":action1,action2,action3,action4");
        let perm7: Permission = Permission::new("domain1:action1,action3:target1, target2");
        let perm7b: Permission = Permission::new("domain1:action5");
        let perm8: Permission = Permission::new("");

        assert_eq!(perm5.implies_from_perm(&perm1), true);
        assert_eq!(perm5.implies_from_perm(&perm2), true);
        assert_eq!(perm5.implies_from_perm(&perm3), true);
        assert_eq!(perm5.implies_from_perm(&perm4), true);
        assert_eq!(perm1.implies_from_perm(&perm5), false);
        assert_eq!(perm3.implies_from_perm(&perm5), false);
        assert_eq!(perm6.implies_from_perm(&perm7), true);
        assert_eq!(perm7.implies_from_perm(&perm6), false);
        assert_eq!(perm6.implies_from_perm(&perm7b), false);
        assert_eq!(perm7b.implies_from_perm(&perm6), false);
        assert_eq!(perm8.implies_from_perm(&perm1), true);
        assert_eq!(perm1.implies_from_perm(&perm8), false);
        assert_eq!(perm8.implies_from_perm(&perm2), true);
        assert_eq!(perm2.implies_from_perm(&perm8), false);
        assert_eq!(perm8.implies_from_perm(&perm3), true);
        assert_eq!(perm3.implies_from_perm(&perm8), false);
        assert_eq!(perm8.implies_from_perm(&perm4), true);
        assert_eq!(perm4.implies_from_perm(&perm8), false);
        assert_eq!(perm8.implies_from_perm(&perm5), true);
        assert_eq!(perm5.implies_from_perm(&perm8), false);
        assert_eq!(perm8.implies_from_perm(&perm6), true);
        assert_eq!(perm6.implies_from_perm(&perm8), false);
        assert_eq!(perm8.implies_from_perm(&perm7), true);
        assert_eq!(perm7.implies_from_perm(&perm8), false);
    }

    #[test]
    fn test_internal_is_permitted_from_str(){
        let required: &str = "domain2:action4:target7";
        let assigned: Vec<&str> = vec!["domain1:action1", "domain2:action3,action4"];
        assert_eq!(_is_permitted_from_str(required, assigned.into_iter()), 1);
    }

    #[test]
    fn test_is_permitted_from_perm() {
        let required: &str = "domain2:action4:target7";
        let assigned: Vec<Permission> = vec![Permission::new("domain1:action1"),
                                             Permission::new("domain2:action3,action4")];
        assert_eq!(_is_permitted_from_perm(required, assigned), 1);
    }

}
