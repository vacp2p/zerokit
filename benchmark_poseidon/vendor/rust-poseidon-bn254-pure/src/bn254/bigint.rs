
//
// big integers, represented as little-endian arrays of u32-s
//

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use std::fmt;
use std::cmp::{Ordering,min};

use unroll::unroll_for_loops;

use crate::bn254::platform::*;
use crate::bn254::constant::{PRIME_ARRAY};

//------------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct BigInt<const N: usize>([u32; N]);

#[inline(always)]
pub fn mkBigInt<const N: usize>(ls: [u32; N]) -> BigInt<N> {
  BigInt(ls)
}

pub type BigInt256 = BigInt<8>;
pub type BigInt512 = BigInt<16>;

//------------------------------------------------------------------------------

impl<const N: usize> fmt::Display for BigInt<N> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let _ = f.write_str("0x");
    for i in 0..N {
      let _ = f.write_fmt(format_args!("{:08x}",self.0[N-1-i]));
    }   
    Ok(())
  }
}

impl<const N: usize> BigInt<N> {
  pub fn print(s: &str, A: &BigInt<N>) {
    println!("{} = {}", s, A);
  }
}

//------------------------------------------------------------------------------

impl<const N: usize> BigInt<N> {

  #[inline(always)]
  pub fn unwrap(big: BigInt<N>) -> [u32; N] {
    big.0
  }
 
  #[inline(always)]
  pub const fn make(ls: [u32; N]) -> BigInt<N> { 
    BigInt(ls)
  }

  pub fn truncate1(big : &BigInt<{N+1}>) -> BigInt<N> {
    // let small: [u32; N] = &big.limbs[0..N];
    let mut small: [u32; N] = [0; N];
    for i in 0..N { small[i] = big.0[i]; }
    BigInt(small)
  }

  pub fn zero() -> BigInt<N> {
    BigInt([0; N])
  }

  pub fn from_u32(x: u32) -> BigInt<N> {
    let mut xs = [0; N];
    xs[0] = x;
    BigInt(xs)
  }

  pub fn is_zero(big: &BigInt<N>) -> bool {
    let mut ok : bool = true;
    for i in 0..N {
      if big.0[i] != 0 {
        ok = false;
        break;
      }
    }
    ok
  }

  pub fn is_equal(big1: &BigInt<N>, big2: &BigInt<N>) -> bool {
    let mut ok : bool = true;
    for i in 0..N {
      if big1.0[i] != big2.0[i] {
        ok = false;
        break;
      }
    }
    ok
  }

  pub fn cmp(big1: &BigInt<N>, big2: &BigInt<N>) -> Ordering {
    let mut res : Ordering = Ordering::Equal;
    for i in (0..N).rev() {
      if big1.0[i] < big2.0[i] {
        res = Ordering::Less;
        break;
      }
      if big1.0[i] > big2.0[i] {
        res = Ordering::Greater;
        break;
      }
    }
    res
  }

  pub fn is_lt(big1: &BigInt<N>, big2: &BigInt<N>) -> bool {
    BigInt::cmp(&big1, &big2) == Ordering::Less
  }

  pub fn is_gt(big1: &BigInt<N>, big2: &BigInt<N>) -> bool {
    BigInt::cmp(&big1, &big2) == Ordering::Greater
  }

  pub fn is_le(big1: &BigInt<N>, big2: &BigInt<N>) -> bool {
    !BigInt::is_gt(&big1, &big2)
  }

  pub fn is_ge(big1: &BigInt<N>, big2: &BigInt<N>) -> bool {
    !BigInt::is_lt(&big1, &big2)
  }

  //------------------------------------

  #[inline(always)]
  #[unroll_for_loops]
  pub fn addCarry(big1: &BigInt<N>, big2: &BigInt<N>) -> (BigInt<N>, bool) {
    let mut c  : bool = false;  
    let mut zs : [u32; N] = [0; N];
    for i in 0..N {
      let (z,cout) = addCarry32( big1.0[i] , big2.0[i] , c);
      zs[i] = z;
      c = cout;
    }
    let big: BigInt<N> = BigInt(zs);
    (big, c)
  }

  #[inline(always)]
  #[unroll_for_loops]
  pub fn subBorrow(big1: &BigInt<N>, big2: &BigInt<N>) -> (BigInt<N>, bool) {
    let mut c  : bool = false;  
    let mut zs : [u32; N] = [0; N];
    for i in 0..N {
      let (z,cout) = subBorrow32( big1.0[i] , big2.0[i] , c );
      zs[i] = z;
      c = cout;
    }
    let big: BigInt<N> = BigInt(zs); 
    (big, c)
  }

  pub fn add(big1: &BigInt<N>, big2: &BigInt<N>) -> BigInt<N> {
    let (out,_) = BigInt::addCarry(big1,big2);
    out
  }

  pub fn sub(big1: &BigInt<N>, big2: &BigInt<N>) -> BigInt<N> {
    let (out,_) = BigInt::subBorrow(big1,big2);
    out
  }

  //------------------------------------
  // specialize to the prime number

  #[inline(always)]
  #[unroll_for_loops]
  pub fn is_lt_prime(big: &BigInt<N>) -> bool {
    let mut less: bool = false;
    for i in (0..N).rev() {
      if big.0[i] < PRIME_ARRAY[i] {
        less = true;
        break;
      }
      if big.0[i] > PRIME_ARRAY[i] {
        break;
      }
    }
    less
  }

  #[inline(always)]
  pub fn is_ge_prime(big: &BigInt<N>) -> bool {
    !BigInt::is_lt_prime(big)
  }

  #[inline(always)]
  #[unroll_for_loops]
  pub fn add_prime(big: &BigInt<N>) -> (BigInt<N>, bool) {
    let mut c  : bool = false;  
    let mut zs : [u32; N] = [0; N];
    for i in 0..N {
      let (z,cout) = addCarry32( big.0[i] , PRIME_ARRAY[i] , c );
      zs[i] = z;
      c = cout;
    }
    let big: BigInt<N> = BigInt(zs);
    (big, c)
  }

  #[inline(always)]
  #[unroll_for_loops]
  pub fn subtract_prime(big: &BigInt<N>) -> (BigInt<N>, bool) {
    let mut c  : bool = false;  
    let mut zs : [u32; N] = [0; N];
    for i in 0..N {
      let (z,cout) = subBorrow32( big.0[i] , PRIME_ARRAY[i] , c );
      zs[i] = z;
      c = cout;
    }
    let big: BigInt<N> = BigInt(zs); 
    (big, c)
  }

  #[inline(always)]
  pub fn subtract_prime_if_necessary(big: &BigInt<N>) -> BigInt<N> {
    if BigInt::is_lt_prime(big) {
      *big
    }
    else {
      let (corrected, _) = BigInt::subtract_prime(big);
      corrected
    }
  }

  //------------------------------------

  pub fn scale(scalar: u32, big2: &BigInt<N>) -> (BigInt<N>, u32) {
    let mut c  : u32 = 0;
    let mut zs : [u32; N] = [0; N];
    for i in 0..N {
      let (lo,hi) = mulAdd32(scalar, big2.0[i], c);
      zs[i] = lo;
      c = hi;
    }
    let big: BigInt<N> = BigInt(zs); 
    (big, c)
  }

  #[inline(always)]
  #[unroll_for_loops]
  pub fn scaleAdd(scalar: u32, vector: &BigInt<N>, add: &BigInt<N>) -> (BigInt<N>, u32) {
    let mut c  : u32 = 0;
    let mut zs : [u32; N] = [0; N];
    for i in 0..N {
      let (lo,hi) = mulAddAdd32(scalar, vector.0[i], c, add.0[i]);
      zs[i] = lo;
      c = hi;
    }
    let big: BigInt<N> = BigInt(zs); 
    (big, c)
  }

  #[inline(always)]
  #[unroll_for_loops]
  pub fn multiply<const M: usize>(big1: &BigInt<N>, big2: &BigInt<M>) -> BigInt<{N+M}> {
    let mut product : [u32; N+M] = [0; N+M];
    let mut state   : [u32; N]   = [0; N];
    for j in 0..M {
      let (scaled,carry) = BigInt::scaleAdd( big2.0[j], &big1, &BigInt(state) );
      product[j] = scaled.0[0];
      for i in 1..N { state[i-1] = scaled.0[i] }
      state[N-1] = carry;
    }
    for i in 0..N { 
      product[i+M] = state[i]
    }
  
    BigInt(product)
  }

  #[inline(always)]
  pub fn mul(big1: &BigInt<N>, big2: &BigInt<N>) -> BigInt<{N+N}> {
    BigInt::multiply(big1,big2)
  }

  // TODO: optimize this?!
  pub fn sqr_naive(big: &BigInt<N>) -> BigInt<{N+N}> {
    BigInt::multiply(big,big)
  }

  #[inline(always)]
  pub fn sqr(big: &BigInt<N>) -> BigInt<{N+N}> {
    BigInt::multiply(big,big)
  }

// -----------------------------------------------------------------------------
// half-assed optimization attempts...

/*
  pub fn sqr_also_slower(big: &BigInt<N>) -> BigInt<{N+N}> {

    let mut mul_mtx : [[(u32,u32); N]; N] = [[(0,0); N]; N];
    for i in 0..N {
      for j in i..N {
        // i <= j
        let lo_hi = mulExt32( big.0[i] , big.0[j] );
        mul_mtx[i][j] = lo_hi;
        mul_mtx[j][i] = lo_hi;
      }
    }

    let mut product : [u32; N+N] = [0; N+N];
    let mut state   : [u32; N]   = [0; N];
    for j in 0..N {
      // let (scaled,carry) = BigInt::scaleAdd( big2.0[j], &big1, &BigInt(state) );

      let mut scaled : [u32; N] = [0; N];
      let mut carry  : u32 = 0;
      for k in 0..N {
        // scalar = big2.0[j]
        // vector = big1
        let (lo,hi) = u64AddAdd32( mul_mtx[j][k], carry, state[k] );
        scaled[k] = lo;
        carry     = hi;
      }

      product[j] = scaled[0];
      for i in 1..N { state[i-1] = scaled[i] }
      state[N-1] = carry;
    }

    for i in 0..N { 
      product[i+N] = state[i]
    }
  
    BigInt(product)
  }

// -----------------------------------

  pub fn sqr_is_actually_slower(big: &BigInt<N>) -> BigInt<{N+N}> {

    let mut product : [u32; N+N] = [0; N+N];
    let mut carry   : u64 = 0;

    for k in 0..(N+N-1) {

      let mut sum_lo: u64 = carry;
      let mut sum_hi: u64 = 0;
      for i in 0..min(N,k+1) {
        let j = k - i;
        if j < N && i <= j {
          let (lo,hi) = mulExt32( big.limbs[i], big.limbs[j] );
          sum_lo += (lo as u64);
          sum_hi += (hi as u64);
          if i < j {
            sum_lo += (lo as u64);
            sum_hi += (hi as u64);
          }
        }
      }
      let (u,v) = takeApart64(sum_lo);
      product[k] = u;
      carry = sum_hi + (v as u64);
    }

    product[N+N-1] = (carry as u32);
    BigInt { limbs: product }
  }

*/

}

//------------------------------------------------------------------------------
