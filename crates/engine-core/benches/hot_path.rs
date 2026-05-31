use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use engine_core::Engine;

// ~200-byte payloads typical of a masked LLM prompt turn.
const SAMPLE_PII: &str = concat!(
    "Patient Jane Doe (DOB 1982-04-17) SSN 575-82-8889 ",
    "CC 4111 1111 1111 1111 email jane@example.com ",
    "phone (555) 867-5309 IP 192.168.1.100 ",
    "routing 021000021 account 00123456789",
);

const SAMPLE_SECRET: &str = concat!(
    "export AWS_KEY=AKIAIOSFODNN7EXAMPLE ",
    "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678 ",
    "DB_URL=postgres://user:password123@db.example.com:5432/mydb",
);

const CLEAN: &str =
    "The quick brown fox jumps over the lazy dog. No sensitive content here at all.";

// ---------------------------------------------------------------------------
// detect
// ---------------------------------------------------------------------------

fn bench_detect(c: &mut Criterion) {
    let engine = Engine::with_default_policy();
    let mut group = c.benchmark_group("detect");

    for (label, text) in [
        ("pii_dense", SAMPLE_PII),
        ("secrets", SAMPLE_SECRET),
        ("clean", CLEAN),
    ] {
        group.bench_with_input(BenchmarkId::new("detect", label), text, |b, text| {
            b.iter(|| engine.detect(black_box(text)));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// mask
// ---------------------------------------------------------------------------

fn bench_mask(c: &mut Criterion) {
    let engine = Engine::with_default_policy();
    let mut group = c.benchmark_group("mask");

    for (label, text) in [
        ("pii_dense", SAMPLE_PII),
        ("secrets", SAMPLE_SECRET),
        ("clean", CLEAN),
    ] {
        group.bench_with_input(BenchmarkId::new("mask", label), text, |b, text| {
            b.iter(|| engine.mask(black_box(text), None, None));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// mask → rehydrate roundtrip
// ---------------------------------------------------------------------------

fn bench_mask_rehydrate(c: &mut Criterion) {
    let engine = Engine::with_default_policy();

    c.bench_function("mask_rehydrate_roundtrip", |b| {
        b.iter(|| {
            let result = engine.mask(black_box(SAMPLE_PII), None, None);
            let cid = result.correlation_id.clone();
            engine.rehydrate(black_box(&result.text), black_box(&cid), None)
        });
    });
}

// ---------------------------------------------------------------------------
// prefilter only
// ---------------------------------------------------------------------------

fn bench_prefilter(c: &mut Criterion) {
    use engine_core::detectors::prefilter::scan_hints;
    let mut group = c.benchmark_group("prefilter");

    for (label, text) in [
        ("pii_dense", SAMPLE_PII),
        ("secrets", SAMPLE_SECRET),
        ("clean", CLEAN),
    ] {
        group.bench_with_input(BenchmarkId::new("scan_hints", label), text, |b, text| {
            b.iter(|| scan_hints(black_box(text)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_detect,
    bench_mask,
    bench_mask_rehydrate,
    bench_prefilter
);
criterion_main!(benches);
