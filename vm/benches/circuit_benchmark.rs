// Copyright (c) zkMove Authors

use criterion::{criterion_group, criterion_main, measurement::Measurement, BatchSize, Criterion};

//
// Circuit benchmarks
//

fn circuit_benchmark<M: Measurement + 'static>(c: &mut Criterion<M>) {
    //

    c.bench_function("fast circuit", |bencher| {
        bencher.iter_batched(|| {}, |_| {}, BatchSize::LargeInput)
    });
}

criterion_group!(
    name = circuit_benches;
    config = Criterion::default().sample_size(10);
    targets = circuit_benchmark
);

criterion_main!(circuit_benches);
