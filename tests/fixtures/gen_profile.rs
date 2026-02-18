// Simple program to generate a profiling fixture.
// Compile and run with samply:
//   rustc tests/fixtures/gen_profile.rs -o /tmp/gen_profile
//   samply record --save-only -o tests/fixtures/profile.json.gz -- /tmp/gen_profile

use std::hint::black_box;

#[inline(never)]
fn hot_function() {
    let mut sum = 0u64;
    for i in 0..500_000_000u64 {
        sum = sum.wrapping_add(i);
    }
    black_box(sum);
}

#[inline(never)]
fn medium_function() {
    let mut sum = 0u64;
    for i in 0..200_000_000u64 {
        sum = sum.wrapping_add(i.wrapping_mul(i));
    }
    black_box(sum);
}

#[inline(never)]
fn cold_function() {
    let mut sum = 0u64;
    for i in 0..50_000_000u64 {
        sum = sum.wrapping_add(i.wrapping_mul(3));
    }
    black_box(sum);
}

#[inline(never)]
fn caller_a() {
    hot_function();
    medium_function();
}

#[inline(never)]
fn caller_b() {
    hot_function();
    cold_function();
}

fn main() {
    for _ in 0..3 {
        caller_a();
        caller_b();
    }
}
