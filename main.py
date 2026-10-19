## Imports
from crypto_utils import *
from test import *

## Tests

test_crypto_utils()

## Bob genere sa paire de cles RSA

## Bob publie sa cle publique RSA



## Alice genere une cle AES et HMAC

## Alice chiffre les deux cles avec la cle de Bob

## Alice chiffre le message en AES-256-CBC avec un IV neuf

## Alice calcule le HMAC-SHA256 de l'IV + msg chiffre



## Alice transmets les cles a Bob



## Bob dechiffre les cles avec sa cle privee

## Bob verifie le HMAC et rejette le paquet s'il est faux

## Bob dechiffre le message