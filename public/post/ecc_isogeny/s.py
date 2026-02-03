from sage.all import *
E = EllipticCurve(GF(131), [-3, 3]) #(E): Y^2 = X^3 + -3X + 3
n = E.order() #Get order of curve
print(n)