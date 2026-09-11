
//
// standard representation of field elements
//
// note: this is used primarily for input/output; 
// for actual computations, use the Montgomery representation!
//

#![allow(dead_code)]
#![allow(non_snake_case)]

use std::fmt;

use crate::bn254::bigint::*;
use crate::bn254::constant::*;
use crate::bn254::montgomery::*;

//------------------------------------------------------------------------------

type Big = BigInt<8>;

#[derive(Copy, Clone)]
pub struct Felt(Big);

//------------------------------------------------------------------------------

impl fmt::Display for Felt {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.write_fmt(format_args!("{}",self.0))
  }
}

impl Felt {
  pub fn print(s: &str, A: &Felt) {
    println!("{} = {}", s, A);
  }
}

//------------------------------------------------------------------------------

impl Felt {

  #[inline(always)]
  pub fn unwrap(felt: Felt) -> Big {
    felt.0
  }

  pub const fn unsafe_make( xs: [u32; 8] ) -> Felt {
    Felt(BigInt::make(xs))
  }

  pub fn checked_make( xs: [u32; 8] ) -> Felt {
    let big: Big = BigInt::make(xs);
    if BigInt::is_lt_prime(&big) {
      Felt(big)
    }
    else {
      panic!("Felt::checked_make: not in range")
    }
  }

  // convert to Montgomery representation
  pub fn to_mont(fld: &Felt) -> Mont {
    Mont::unsafe_convert_from_big( &fld.0 )
  }

  // convert from Montgomery representation
  pub fn from_mont(mont: &Mont) -> Felt {
    Felt(Mont::convert_to_big(&mont))
  }

  pub fn zero() -> Felt {
    Felt(BigInt::zero())
  }

  pub fn from_u32(x: u32) -> Felt {
    Felt(BigInt::from_u32(x))
  }

  pub fn is_equal(fld1: &Felt, fld2: &Felt) -> bool {
    BigInt::is_equal(&fld1.0, &fld2.0)
  }

  pub fn neg(fld: &Felt) -> Felt {
    if BigInt::is_zero(&fld.0) {
      Felt::zero()
    }
    else {
      Felt(BigInt::sub(&FIELD_PRIME, &fld.0))
    }
  }

  pub fn add(fld1: &Felt, fld2: &Felt) -> Felt {
    let (A, _) = BigInt::addCarry(&fld1.0, &fld2.0);
    let  B     = BigInt::subtract_prime_if_necessary(&A);
    Felt(B) 
  }

  pub fn sub(fld1: &Felt, fld2: &Felt) -> Felt {
    let (big, carry) = BigInt::subBorrow(&fld1.0, &fld2.0);
    if carry {
      let (corrected, _) = BigInt::add_prime(&big);
      Felt(corrected)
    }
    else {
      Felt(big)
    }
  }

  pub fn dbl(fld: &Felt) -> Felt {
    Felt::add(&fld, &fld)
  }

  pub fn sqr(fld: &Felt) -> Felt {
    let mont = Felt::to_mont(&fld);
    Felt::from_mont(&Mont::sqr(&mont))
  }

  pub fn mul(fld1: &Felt, fld2: &Felt) -> Felt {
    let mont1 = Felt::to_mont(&fld1);
    let mont2 = Felt::to_mont(&fld2);
    Felt::from_mont(&Mont::mul(&mont1,&mont2))
  }

}

//------------------------------------------------------------------------------
