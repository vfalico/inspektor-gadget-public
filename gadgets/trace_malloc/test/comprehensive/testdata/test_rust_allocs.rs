// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Comprehensive Rust allocation test for trace-malloc
// Tests: Vec, Box, String, HashMap, intentional leak
use std::collections::HashMap;

fn main() {
    println!("=== Vec allocations ===");
    {
        let mut v: Vec<i32> = Vec::new();
        for i in 0..1000 {
            v.push(i);
        }
        v.clear();
        v.shrink_to_fit();
    }

    println!("=== Box allocations ===");
    for i in 0..10 {
        let b = Box::new(vec![i; 256]);
        drop(b);
    }

    println!("=== String allocations ===");
    {
        let mut s = String::new();
        for _ in 0..100 {
            s.push_str("hello world ");
        }
        s.clear();
        s.shrink_to_fit();
    }

    println!("=== HashMap allocations ===");
    {
        let mut m: HashMap<i32, String> = HashMap::new();
        for i in 0..100 {
            m.insert(i, format!("value_{}", i));
        }
        m.clear();
    }

    // Intentional leak
    println!("=== intentional leak ===");
    let leaked = Box::new(vec![42u8; 4096]);
    std::mem::forget(leaked);

    println!("All Rust tests passed.");
}
