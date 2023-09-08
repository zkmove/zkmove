use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::dev::{MockProver, VerifyFailure};
use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::plonk::{Circuit, Error};
use logger::{debug, trace};
use plotters::prelude::{IntoDrawingArea, SVGBackend, WHITE};

// number of circuit rows cannot exceed 2^MAX_K
pub const MAX_K: u32 = 18;
pub const MIN_K: u32 = 1;

/// find the minimum k that satisfies the circuit row number less than 2^k
pub fn find_best_k<F: FieldExt, ConcreteCircuit: Circuit<F>>(
    circuit: &ConcreteCircuit,
    instance: Vec<Vec<F>>,
) -> VmResult<u32> {
    let mut k = MIN_K;
    while k <= MAX_K {
        trace!("Try k={}...", k);
        let not_enough_rows_error = Error::NotEnoughRowsAvailable { current_k: k };
        let result = MockProver::run(k, circuit, instance.clone());
        match result {
            Ok(r) => {
                // Ensure that no constraints will get poisoned.
                // This can happen if the circuit is principally big enough, but the
                // constraint count exceeds the number of usable rows
                // (2^k - 1 - blinding_factors).
                let _ = r.verify().map_err(|e| {
                    if e.iter()
                        .any(|e| matches!(e, VerifyFailure::ConstraintPoisoned { .. }))
                    {
                        k += 1;
                    }
                });
                break;
            }
            Err(e) => {
                if e.to_string() == not_enough_rows_error.to_string() {
                    k += 1;
                } else {
                    debug!("Prover Error: {:?}", e);
                    return Err(RuntimeError::new(StatusCode::ProofSystemError(e)));
                }
            }
        }
    }
    Ok(k)
}

pub fn mock_prove_circuit<F: FieldExt, ConcreteCircuit: Circuit<F>>(
    circuit: &ConcreteCircuit,
    instance: Vec<Vec<F>>,
    k: u32,
) -> VmResult<()> {
    let prover = MockProver::run(k, circuit, instance).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}

pub fn print_circuit_layout<F: FieldExt, ConcreteCircuit: Circuit<F>>(
    k: u32,
    circuit: &ConcreteCircuit,
) {
    let root = SVGBackend::new("layout.svg", (3840, 2160)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Circuit Layout", ("sans-serif", 60)).unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .mark_equality_cells(true)
        .show_equality_constraints(true)
        .render(k, circuit, &root)
        .unwrap();
}
