from mpmath import mp, mpf, exp, pi, sqrt, floor


def FpToHex(x, precision):
  """Converts a floating-point number to a hex string.

  Args:
    x: A floating-point, possibly high-precision, number from [0, 1.0).
    precision: The number of significant hexadecimal digits.
  Returns:
    a string of exactly precision length.

  Ex:
    FpToHex(1 / 2.3, 6)
    "6F4DE9" 
  """
  x += 8 * mpf(16) ** (-precision - 1)  # doing rounding correctly
  assert x < 1.0
  result = ""
  for i in range(precision):
    digit = int(floor(x * 16))
    x = x * 16 - digit
    result += "{0:X}".format(digit)
  return result


def FormatHex(s, radixlength):
  """Outputs a hex string s as a 'C' array of hex integers.

  Args:
    s: The input string of hex digits.
    radixlength: The length of "digits" into which the string is going to be 
        chopped. Must be between 1 and 64.      

  Returns:
    A little-endian string that can be used as a constant initializer in C code.

  Ex:
    FormatHex("DEAD", 3) outputs
    "{0xEAD}, {0x00D}"
  """

  result = "{"

  while len(s) > radixlength:
    result += "0x" + s[-radixlength:]
    s = s[:-radixlength]
    if len(s) > 0:
      result += ", "

  if len(s) > 0:
    result += "0x{}{}".format("0" * (radixlength - len(s)), s)

  result += "}"

  return result


def main():
  # Set precision of multi-precision arithmetic to be much higher
  # than actual accuracy that is required.  
  mp.prec = 256

  # This is the accuracy (total variation distance) with which we approximate
  # the target distribution. 
  approx = mpf(2) ** (-192)
  
  # The parameter of the discrete Gaussian distribution. 
  sigma = 8 / sqrt(2 * pi)

  pdf_prop = []
  i = 0
  while True:
    x = exp(-i ** 2 / (2 * sigma ** 2))
    
    # An artifact of the fact that the sign of the discrete Gaussian is sampled
    # separately at random, the probability mass assigned to 0 is halved.
    if i == 0:  
      x /= 2
      
    if x / (x + sum(pdf_prop)) < approx:
      break
    pdf_prop.append(x)
    i += 1

  pdf = [x / sum(pdf_prop) for x in pdf_prop]
  
  print "static uint64_t lwe_table[{}][3] = {{".format(len(pdf))

  cumsum = 0
  for i, x in enumerate(pdf):
    cumsum += x
    
    cumsum = min(cumsum, mpf(1.0) - approx)
          
    s = FpToHex(cumsum, 48)  # Convert the string to hex 
    print "  {}{}".format(FormatHex(s, 16), "," if i < len(pdf) - 1 else "")
  
  print "}}"

if __name__ == '__main__':
  main()
