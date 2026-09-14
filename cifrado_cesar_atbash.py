#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 SISTEMA DE CIFRADO Y DESCIFRADO -- CESAR Y ATBASH
================================================================================

Contexto (para tu Introduccion):
---------------------------------
El sabio arabe Abu Yusuf Ya'qub ibn Ishaq al-Kindi (Al-Kindi, s. IX d.C.),
conocido como "el filosofo de los arabes", escribio "Risala fi Istikhraj
al-Mu'amma" ("Manuscrito sobre el Descifrado de Mensajes Criptograficos"),
el primer texto conocido que describe el CRIPTOANALISIS POR ANALISIS DE
FRECUENCIAS. Su idea central: en cualquier idioma natural, ciertas letras
aparecen con una frecuencia estadistica predecible (en espanol, la "e" y la
"a" son mucho mas comunes que la "k" o la "w"). Un cifrado por sustitucion
monoalfabetica (como Cesar o Atbash) NO oculta esas frecuencias, solo las
reetiqueta -- por lo que basta con comparar las frecuencias del texto
cifrado contra las frecuencias esperadas del idioma para romper el cifrado
sin conocer la llave. Esto es exactamente lo que implementa la funcion
`chi_cuadrada_texto()` y `descifrar_automatico()` de este programa: es una
version moderna, automatizada, del metodo de Al-Kindi. Por esta misma razon
el cifrado Cesar y el Atbash ya NO son viables como metodos de proteccion
de datos: cualquier atacante (humano o, como aqui, una maquina) puede
romperlos en milisegundos sin la llave, usando solo estadistica del idioma.

Que resuelve este programa (segun la rubrica del proyecto):
-------------------------------------------------------------
1. Permite definir el conjunto de caracteres/alfabeto a usar (basado en
   codigo ASCII), incluyendo alfabetos personalizados.
2. Permite CIFRAR eligiendo el modulo: Cesar (con desplazamiento) o Atbash.
3. Permite DESCIFRAR sin que el usuario indique el metodo: el sistema
   prueba automaticamente Atbash y los N desplazamientos posibles de
   Cesar, califica cada resultado con analisis de frecuencias (Al-Kindi)
   y muestra UNICAMENTE la linea de texto plano correcta. No hay
   intervencion humana en la decision de cual es el resultado valido.

Ejecucion:
----------
    python3 cifrado_cesar_atbash.py

================================================================================
"""

import string
import sys

# Algunas terminales de Windows (CMD/PowerShell antiguos) usan una
# codificacion heredada (cp1252/cp437) que puede fallar al imprimir
# acentos o la "ñ". Esto fuerza la salida a UTF-8 cuando es posible,
# para evitar UnicodeEncodeError al imprimir texto en español.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ==============================================================================
# 1. FRECUENCIAS DE LETRAS EN ESPANOL (referencia estadistica para Al-Kindi)
# ==============================================================================
# Porcentaje aproximado de aparicion de cada letra en textos largos en espanol.
# Fuente: frecuencias estandar de letras del idioma espanol (dominio publico,
# ampliamente reproducidas en literatura de criptografia clasica).
FREQ_ESPANOL = {
    "a": 12.53, "b": 1.42, "c": 4.68, "d": 5.86, "e": 13.68, "f": 0.69,
    "g": 1.01, "h": 0.70, "i": 6.25, "j": 0.44, "k": 0.02, "l": 4.97,
    "m": 3.15, "n": 6.71, "ñ": 0.31, "o": 8.68, "p": 2.51, "q": 0.88,
    "r": 6.87, "s": 7.98, "t": 4.63, "u": 3.93, "v": 0.90, "w": 0.02,
    "x": 0.22, "y": 0.90, "z": 0.52,
}


# ==============================================================================
# 2. CONSTRUCCION DEL ALFABETO / CONJUNTO DE CARACTERES (BASE ASCII)
# ==============================================================================
def construir_alfabeto_por_ascii(inicio: int, fin: int) -> str:
    """Construye una cadena de caracteres a partir de un rango de codigos ASCII."""
    if inicio > fin:
        inicio, fin = fin, inicio
    return "".join(chr(c) for c in range(inicio, fin + 1))


ALFABETOS_PREDEFINIDOS = {
    "1": ("Minusculas (a-z)", string.ascii_lowercase),
    "2": ("Mayusculas (A-Z)", string.ascii_uppercase),
    "3": ("Letras completas (a-z y A-Z)", string.ascii_letters),
    "4": ("Letras + digitos", string.ascii_letters + string.digits),
    "5": ("ASCII imprimible completo (32-126)", construir_alfabeto_por_ascii(32, 126)),
}


def elegir_alfabeto() -> str:
    """Menu para que el usuario alimente al sistema con el conjunto de
    caracteres/simbolos (esten o no en ASCII estandar) que se usara."""
    print("\n--- Conjunto de caracteres (alfabeto) a utilizar ---")
    for clave, (nombre, _) in ALFABETOS_PREDEFINIDOS.items():
        print(f"  {clave}) {nombre}")
    print("  6) Alfabeto personalizado (cualquier simbolo que definas)")
    print("  7) Rango de codigo ASCII personalizado")

    opcion = input("Selecciona una opcion: ").strip()

    if opcion in ALFABETOS_PREDEFINIDOS:
        return ALFABETOS_PREDEFINIDOS[opcion][1]

    if opcion == "6":
        alfabeto = input(
            "Escribe el conjunto de caracteres/simbolos a usar "
            "(pueden ser letras, numeros, simbolos, emojis, etc.): "
        )
        if not alfabeto:
            print("Alfabeto vacio, se usara minusculas por defecto.")
            return string.ascii_lowercase
        return alfabeto

    if opcion == "7":
        try:
            inicio = int(input("Codigo ASCII inicial (ej. 32): ").strip())
            fin = int(input("Codigo ASCII final (ej. 126): ").strip())
            return construir_alfabeto_por_ascii(inicio, fin)
        except ValueError:
            print("Valores invalidos, se usara ASCII imprimible completo.")
            return ALFABETOS_PREDEFINIDOS["5"][1]

    print("Opcion invalida, se usara minusculas por defecto.")
    return string.ascii_lowercase


# ==============================================================================
# 3. CIFRADO / DESCIFRADO CESAR
# ==============================================================================
def cifrar_cesar(texto: str, alfabeto: str, desplazamiento: int) -> str:
    """Cifra 'texto' desplazando cada caracter 'desplazamiento' posiciones
    dentro de 'alfabeto'. Los caracteres que no estan en el alfabeto se
    dejan sin cambio (por ejemplo espacios, si no se incluyeron)."""
    n = len(alfabeto)
    salida = []
    for caracter in texto:
        indice = alfabeto.find(caracter)
        if indice == -1:
            salida.append(caracter)
        else:
            nuevo_indice = (indice + desplazamiento) % n
            salida.append(alfabeto[nuevo_indice])
    return "".join(salida)


def descifrar_cesar(texto: str, alfabeto: str, desplazamiento: int) -> str:
    """Descifrar Cesar es cifrar con el desplazamiento inverso."""
    return cifrar_cesar(texto, alfabeto, -desplazamiento)


# ==============================================================================
# 4. CIFRADO / DESCIFRADO ATBASH
# ==============================================================================
def cifrar_atbash(texto: str, alfabeto: str) -> str:
    """Atbash invierte el alfabeto: la primera posicion se intercambia con
    la ultima, la segunda con la penultima, etc. Es su propio inverso."""
    n = len(alfabeto)
    salida = []
    for caracter in texto:
        indice = alfabeto.find(caracter)
        if indice == -1:
            salida.append(caracter)
        else:
            salida.append(alfabeto[n - 1 - indice])
    return "".join(salida)


# Atbash es simetrico: la misma funcion cifra y descifra.
descifrar_atbash = cifrar_atbash


# ==============================================================================
# 5. CRIPTOANALISIS POR FRECUENCIAS (metodo de Al-Kindi, automatizado)
# ==============================================================================
def chi_cuadrada_texto(texto: str) -> float:
    """
    Calcula que tanto se parece 'texto' al espanol natural, usando la
    prueba estadistica chi-cuadrada contra las frecuencias esperadas de
    FREQ_ESPANOL. MIENTRAS MAS BAJO el valor, MAS PARECIDO es el texto
    al espanol real (mejor candidato a ser el texto plano correcto).

    Esta es la formalizacion moderna del criptoanalisis por frecuencias
    que Al-Kindi describio por primera vez en el siglo IX.
    """
    letras = [c.lower() for c in texto if c.lower() in FREQ_ESPANOL]
    total = len(letras)
    if total == 0:
        return float("inf")

    conteo = {letra: 0 for letra in FREQ_ESPANOL}
    for letra in letras:
        conteo[letra] += 1

    chi2 = 0.0
    for letra, frecuencia_esperada_pct in FREQ_ESPANOL.items():
        esperado = (frecuencia_esperada_pct / 100.0) * total
        observado = conteo[letra]
        if esperado > 0:
            chi2 += ((observado - esperado) ** 2) / esperado
    return chi2


def descifrar_automatico(texto_cifrado: str, alfabeto: str):
    """
    Determina AUTOMATICAMENTE (sin que el humano elija) si el mensaje fue
    cifrado con Atbash o con Cesar -y en ese caso, con que modulo/
    desplazamiento- probando todas las posibilidades y quedandose con la
    que mejor puntua contra las frecuencias del espanol.

    Devuelve: (metodo:str, desplazamiento:int|None, texto_plano:str, chi2:float)
    """
    candidatos = []

    # Candidato Atbash
    texto_atbash = descifrar_atbash(texto_cifrado, alfabeto)
    candidatos.append(("ATBASH", None, texto_atbash, chi_cuadrada_texto(texto_atbash)))

    # Un candidato por cada desplazamiento posible de Cesar
    n = len(alfabeto)
    for desplazamiento in range(n):
        texto_cesar = descifrar_cesar(texto_cifrado, alfabeto, desplazamiento)
        candidatos.append(
            ("CESAR", desplazamiento, texto_cesar, chi_cuadrada_texto(texto_cesar))
        )

    # El "ganador" es el de menor chi-cuadrada (mas parecido al espanol real)
    mejor = min(candidatos, key=lambda c: c[3])
    return mejor


# ==============================================================================
# 6. MENU / INTERFAZ DE TERMINAL
# ==============================================================================
def menu():
    print("=" * 70)
    print(" SISTEMA DE CIFRADO / DESCIFRADO -- CESAR Y ATBASH")
    print(" Deteccion automatica basada en analisis de frecuencias (Al-Kindi)")
    print("=" * 70)

    alfabeto = elegir_alfabeto()
    print(f"\nAlfabeto activo ({len(alfabeto)} simbolos):")
    print(alfabeto)

    while True:
        print("\n" + "-" * 70)
        print("Que deseas hacer?")
        print("  1) Cifrar un mensaje")
        print("  2) Descifrar un mensaje (deteccion automatica, sin elegir metodo)")
        print("  3) Cambiar el alfabeto")
        print("  4) Salir")
        opcion = input("Opcion: ").strip()

        if opcion == "1":
            print("\nModulo de cifrado:")
            print("  a) Cesar")
            print("  b) Atbash")
            submodo = input("Selecciona (a/b): ").strip().lower()
            mensaje = input("Escribe el mensaje a cifrar: ")

            if submodo == "a":
                try:
                    desplazamiento = int(
                        input(f"Desplazamiento / modulo (0 a {len(alfabeto) - 1}): ")
                    )
                except ValueError:
                    print("Desplazamiento invalido.")
                    continue
                cifrado = cifrar_cesar(mensaje, alfabeto, desplazamiento)
                print(f"\n>> Cifrado con CESAR (modulo={desplazamiento}):")
                print(cifrado)
            elif submodo == "b":
                cifrado = cifrar_atbash(mensaje, alfabeto)
                print("\n>> Cifrado con ATBASH:")
                print(cifrado)
            else:
                print("Opcion invalida.")

        elif opcion == "2":
            mensaje = input("\nEscribe el mensaje cifrado a descifrar: ")
            metodo, desplazamiento, texto_plano, score = descifrar_automatico(
                mensaje, alfabeto
            )
            print("\n" + "=" * 70)
            if metodo == "ATBASH":
                print("Metodo detectado automaticamente: ATBASH")
            else:
                print(f"Metodo detectado automaticamente: CESAR (modulo = {desplazamiento})")
            print(f"(Puntaje chi-cuadrada del resultado: {score:.2f}; entre mas bajo, mejor)")
            print("-" * 70)
            print("MENSAJE DESCIFRADO:")
            print(texto_plano)
            print("=" * 70)

        elif opcion == "3":
            alfabeto = elegir_alfabeto()
            print(f"\nAlfabeto activo ({len(alfabeto)} simbolos):")
            print(alfabeto)

        elif opcion == "4":
            print("Saliendo del sistema. Hasta luego.")
            sys.exit(0)

        else:
            print("Opcion no valida, intenta de nuevo.")


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nPrograma interrumpido por el usuario.")
        sys.exit(0)
