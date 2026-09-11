
//
// Montgomery representation of field elements
//

#![allow(dead_code)]
#![allow(non_snake_case)]

use std::fmt;

use unroll::unroll_for_loops;

use crate::bn254::platform::*;
use crate::bn254::bigint::*;
use crate::bn254::constant::*;

//------------------------------------------------------------------------------

type Big = BigInt<8>;

#[derive(Copy, Clone)]
pub struct Mont(Big);

pub const MONT_R1 : Mont = Mont(BIG_R1);
pub const MONT_R2 : Mont = Mont(BIG_R2);
pub const MONT_R3 : Mont = Mont(BIG_R3);

//------------------------------------------------------------------------------

impl Mont {

  #[inline(always)]
  pub fn unwrap(mont: Mont) -> Big {
    mont.0
  }

  #[inline(always)]
  pub const fn unsafe_make( xs: [u32; 8] ) -> Mont {
    Mont(BigInt::make(xs))
  }

  #[inline(always)]
  pub fn zero() -> Mont {
    Mont(BigInt::zero())
  }

  pub fn is_equal(mont1: &Mont, mont2: &Mont) -> bool {
    BigInt::is_equal(&mont1.0, &mont2.0)
  }

  pub fn neg(mont: &Mont) -> Mont {
    if BigInt::is_zero(&mont.0) {
      Mont::zero()
    }
    else {
      Mont(BigInt::sub(&FIELD_PRIME, &mont.0))
    }
  }

  #[inline(always)]
  pub fn add(mont1: &Mont, mont2: &Mont) -> Mont {
    let (A, _) = BigInt::addCarry(&mont1.0, &mont2.0);
    let  B     = BigInt::subtract_prime_if_necessary(&A);
    Mont(B) 
  }

  #[inline(always)]
  pub fn sub(mont1: &Mont, mont2: &Mont) -> Mont {
    let (big, carry) = BigInt::subBorrow(&mont1.0, &mont2.0);
    if carry {
      let (corrected, _) = BigInt::add_prime(&big);
      Mont(corrected)
    }
    else {
      Mont(big)
    }
  }

  #[inline(always)]
  pub fn dbl(mont: &Mont) -> Mont {
    Mont::add(&mont, &mont)
  }

  // the Montgomery reduction algorithm
  // <https://en.wikipedia.org/wiki/Montgomery_modular_multiplication#Montgomery_arithmetic_on_multiprecision_integers>
  fn redc_safe(input: BigInt<16>) -> Big {

    let mut T: [u32; 17] = [0; 17];
    for i in 0..16 { T[i] = BigInt::unwrap(input)[i]; }

    for i in 0..8 {
      let mut carry: u32 = 0;
      let m: u32 = mulTrunc32( T[i] , MONT_Q );
      for j in 0..8 {
        let (lo,hi) = mulAddAdd32( m, BigInt::unwrap(FIELD_PRIME)[j], carry, T[i+j] );
        T[i+j] = lo;
        carry  = hi;
      }
      for j in 8..(17-i) {
        let (x,c) = addCarry32_( T[i+j] , carry );
        T[i+j] = x;
        carry  = boolToU32(c);
      }
    }

    let mut S : [u32; 9] = [0; 9];
    for i in 0..9 { S[i] = T[8+i]; }

    let A     :  BigInt<9>       = BigInt::make(S);
    let (B,c) : (BigInt<9>,bool) = BigInt::subBorrow( &A , &PRIME_EXT );

    if c {
      // `A - prime < 0` is equivalent to `A < prime` 
      BigInt::truncate1(&A)
    }
    else {
      // `A - prime >= 0` is equivalent to `A >= prime`
      BigInt::truncate1(&B)
    }
  }

  // we can abuse the fact that we know the prime number `p`,
  // for which `p < 2^254` so we won't overflow in the 17th word
  
  #[unroll_for_loops]
  fn redc(input: BigInt<16>) -> Big {

    let mut T: [u32; 16] = BigInt::unwrap(input);

    for i in 0..8 {
      let mut carry: u32 = 0;
      let m: u32 = mulTrunc32( T[i] , MONT_Q );
      for j in 0..8 {
        let (lo,hi) = mulAddAdd32( m, PRIME_ARRAY[j], carry, T[i+j] );
        T[i+j] = lo;
        carry  = hi;
      }
      for j in 8..(16-i) {
        let (x,c) = addCarry32_( T[i+j] , carry );
        T[i+j] = x;
        carry  = boolToU32(c);
      }
    }

    let mut S : [u32; 8] = [0; 8];
    for i in 0..8 { S[i] = T[8+i]; }

    let A : Big = BigInt::make(S);
    let B : Big = BigInt::subtract_prime_if_necessary(&A); 
    B
  }

  pub fn sqr(mont: &Mont) -> Mont {
    let large = BigInt::sqr(&mont.0);
    Mont(Mont::redc(large))
  }

  pub fn mul(mont1: &Mont, mont2: &Mont) -> Mont {
    let large = BigInt::mul(&mont1.0, &mont2.0);
    Mont(Mont::redc(large))
  }

  // this does conversion from the standard representation
  // we assume the input is in the range `[0..p-1]`
  pub fn unsafe_convert_from_big(input: &Big) -> Mont {
    let mont: Mont = Mont(*input);
    Mont::mul( &mont , &MONT_R2 )
  }

  // this does conversion to the standard representation
  pub fn convert_to_big(mont: &Mont) -> Big {
    let mut tmp: [u32; 16] = [0; 16];
    for i in 0..8 { tmp[i] = BigInt::unwrap(mont.0)[i] } 
    Mont::redc( BigInt::make(tmp) )
  }

  // take a small number, interpret it as modulo P, 
  // and convert to Montgomery representation
  pub fn convert_from_u32(x: u32) -> Mont {
    let big: Big = BigInt::from_u32(x);
    Mont::unsafe_convert_from_big( &big )
  }

}

//------------------------------------------------------------------------------

// prints the internal representation
impl fmt::Debug for Mont {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let _   = f.write_str("[");
    let res = f.write_fmt(format_args!("{}",self.0));
    let _   = f.write_str("]");
    res
  }
}

// prints the standard representation
impl fmt::Display for Mont {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let big: Big = Mont::convert_to_big(&self);
    f.write_fmt(format_args!("{}",big))
  }
}

//------------------------------------------------------------------------------

impl Mont {
  pub fn print_internal(s: &str, A: &Mont) {
    println!("{} = [{}]", s, A.0);
  }

  pub fn print_standard(s: &str, A: &Mont) {
    println!("{} = {}", s, Mont::convert_to_big(A) ) ;
  }

  pub fn print(s: &str, A: &Mont) {
    Mont::print_standard(&s, &A);
  }
}

//------------------------------------------------------------------------------
