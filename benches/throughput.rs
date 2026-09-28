use criterion::{black_box, criterion_group, criterion_main, Criterion};
use flight_tape::{Ring, RingConfig};
use tempfile::TempDir;

fn bench_append(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let mut ring = Ring::open(dir.path(), RingConfig::default()).unwrap();
    c.bench_function("append 1k frames", |b| {
        b.iter(|| {
            ring.record(
                "bench",
                "criterion",
                serde_json::json!({"i": black_box(1), "note": "throughput probe"}),
            )
            .unwrap();
        })
    });
}

criterion_group!(benches, bench_append);
criterion_main!(benches);
