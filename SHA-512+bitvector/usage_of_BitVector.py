#!/usr/bin/env python3
 
 
import sys
from BitVector import *
# The BitVector class is for a memory-efficient packed representation of bit arrays and for logical operations on such arrays. 
# https://engineering.purdue.edu/kak/dist/BitVector-1.3.2.html
def exercise():
  message = "Practice makes perfect"

  bv = BitVector(textstring=message)
  print('textstring', bv)
  print()
  bv = BitVector(bitstring="101111010101010")
  print('bitstring', bv)
  print()
  bv = BitVector(hexstring="6a09e667f3bcc908")
  print('hexstring', bv)
  print()
  bv = BitVector(intVal=1, size=1) + BitVector(intVal=0, size=127)
  print('intVal', bv)
  print()
  zeros = [0]*128
  bv = BitVector(bitlist=zeros) 
  print('bitlist', bv)
  print()

exercise()  
