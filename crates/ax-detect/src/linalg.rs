//! Minimal, deterministic linear algebra for the multivariate detector.
//!
//! Just enough to compute a squared Mahalanobis distance without pulling in a
//! matrix crate: a Cholesky factorization of a symmetric positive-definite
//! matrix and a forward solve. Owning this keeps the math fully mutation-
//! testable and free of any hidden non-determinism.
//!
//! Matrices are row-major `Vec<Vec<f64>>`. All reductions use [`ax_core::det`]
//! so results do not depend on summation order.

use ax_core::det;

/// Lower-triangular Cholesky factor `L` such that `L·Lᵀ == m`, for a symmetric
/// positive-definite `m`. Returns `None` if `m` is not positive-definite
/// (a non-positive pivot is encountered), which the caller treats as "cannot
/// assess" rather than guessing.
pub fn cholesky(m: &[Vec<f64>]) -> Option<Vec<Vec<f64>>> {
    let n = m.len();
    let mut l = vec![vec![0.0_f64; n]; n];
    for i in 0..n {
        for j in 0..=i {
            let products: Vec<f64> = (0..j).map(|k| l[i][k] * l[j][k]).collect();
            let sum = det::det_sum(&products);
            if i == j {
                let diag = m[i][i] - sum;
                if diag <= 0.0 {
                    return None; // not positive-definite
                }
                l[i][j] = diag.sqrt();
            } else {
                l[i][j] = (m[i][j] - sum) / l[j][j];
            }
        }
    }
    Some(l)
}

/// Solves `L·x = b` for lower-triangular `L` by forward substitution.
pub fn forward_solve(l: &[Vec<f64>], b: &[f64]) -> Vec<f64> {
    let n = l.len();
    let mut x = vec![0.0_f64; n];
    for i in 0..n {
        let products: Vec<f64> = (0..i).map(|k| l[i][k] * x[k]).collect();
        x[i] = (b[i] - det::det_sum(&products)) / l[i][i];
    }
    x
}

/// Squared Mahalanobis distance `dᵀ Σ⁻¹ d`, where `chol` is the Cholesky factor
/// of `Σ`. Since `Σ = L·Lᵀ`, solving `L z = d` gives `dᵀΣ⁻¹d = ‖z‖²`.
pub fn mahalanobis_sq(chol: &[Vec<f64>], d: &[f64]) -> f64 {
    let z = forward_solve(chol, d);
    let squares: Vec<f64> = z.iter().map(|v| v * v).collect();
    det::det_sum(&squares)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cholesky_of_identity_is_identity() {
        let id = vec![vec![1.0, 0.0], vec![0.0, 1.0]];
        let l = cholesky(&id).unwrap();
        assert_eq!(l, id);
    }

    #[test]
    fn cholesky_reconstructs_the_matrix() {
        // Σ = [[4,2],[2,3]] is SPD. L·Lᵀ must equal Σ.
        let m = vec![vec![4.0, 2.0], vec![2.0, 3.0]];
        let l = cholesky(&m).unwrap();
        // L = [[2,0],[1, sqrt(2)]]
        assert!((l[0][0] - 2.0).abs() < 1e-12);
        assert!((l[1][0] - 1.0).abs() < 1e-12);
        assert!((l[1][1] - 2.0_f64.sqrt()).abs() < 1e-12);
        // reconstruct
        for i in 0..2 {
            for j in 0..2 {
                let v: f64 = (0..2).map(|k| l[i][k] * l[j][k]).sum();
                assert!((v - m[i][j]).abs() < 1e-12, "({i},{j})");
            }
        }
    }

    #[test]
    fn cholesky_reconstructs_3x3() {
        // A 3×3 SPD matrix exercises off-diagonal entries whose `sum` term is
        // non-zero (unlike 2×2, where the first off-diagonal has empty sum).
        let m = vec![
            vec![4.0, 2.0, 2.0],
            vec![2.0, 5.0, 3.0],
            vec![2.0, 3.0, 6.0],
        ];
        let l = cholesky(&m).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                let v: f64 = (0..3).map(|k| l[i][k] * l[j][k]).sum();
                assert!((v - m[i][j]).abs() < 1e-10, "({i},{j}): {v} vs {}", m[i][j]);
            }
        }
    }

    #[test]
    fn non_positive_definite_returns_none() {
        // negative eigenvalue
        let m = vec![vec![1.0, 2.0], vec![2.0, 1.0]];
        assert_eq!(cholesky(&m), None);
        // zero variance on the diagonal
        let z = vec![vec![0.0, 0.0], vec![0.0, 1.0]];
        assert_eq!(cholesky(&z), None);
    }

    #[test]
    fn forward_solve_is_correct() {
        // L = [[2,0],[1,3]], b = [4, 11] → x = [2, 3]
        let l = vec![vec![2.0, 0.0], vec![1.0, 3.0]];
        let x = forward_solve(&l, &[4.0, 11.0]);
        assert!((x[0] - 2.0).abs() < 1e-12);
        assert!((x[1] - 3.0).abs() < 1e-12);
    }

    #[test]
    fn mahalanobis_with_identity_is_squared_euclidean() {
        let id = vec![vec![1.0, 0.0], vec![0.0, 1.0]];
        // distance² of [3,4] under identity covariance = 9 + 16 = 25
        assert!((mahalanobis_sq(&id, &[3.0, 4.0]) - 25.0).abs() < 1e-12);
    }

    #[test]
    fn mahalanobis_scales_with_variance() {
        // Σ = diag(4, 9): d=[2,3] → (2²/4) + (3²/9) = 1 + 1 = 2
        let chol = cholesky(&[vec![4.0, 0.0], vec![0.0, 9.0]]).unwrap();
        assert!((mahalanobis_sq(&chol, &[2.0, 3.0]) - 2.0).abs() < 1e-12);
    }
}
