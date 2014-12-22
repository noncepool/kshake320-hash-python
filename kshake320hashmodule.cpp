#include <Python.h>

#include "keccak/uint256.h"

#include <vector>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include "keccak/sha3.h"

#define SHAKE320_L  320  // Length in bits
#define KPROOF_OF_WORK_SZ  (SHAKE320_R / 8 * 546)  // KryptoHash Proof of Work Size in bits. It must be a multiple of Keccak Rate.

template<typename T1>
inline uint320 KryptoHash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = { 0 };
    unsigned char scratchpad[KPROOF_OF_WORK_SZ];
    SHAKE320((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]) * 8, scratchpad, sizeof(scratchpad));
    uint320 hash;
    SHAKE320(scratchpad, sizeof(scratchpad) * 8, (unsigned char*)&hash, SHAKE320_L / 8);
    return hash;
}

template<typename T1>
inline uint320 Hash320(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint320 hash;
    SHAKE320((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]) * 8, (unsigned char*)&hash, sizeof(hash));
    return hash;
}

template<typename T1>
inline uint256 Hash256(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA3_256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA3_256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

static void KSHAKE320POW(const char *input, char *output)
{
    uint320 hash = KryptoHash(input, input + 120);
    memcpy(output, &hash, 40);
}

static void GetHash320(const char *input, int len, char *output)
{
    uint320 hash = Hash320(input, input + len);
    memcpy(output, &hash, 40);
}

static void GetHash256(const char *input, int len, char *output)
{
    uint256 hash = Hash256(input, input + len);
    memcpy(output, &hash, 32);
}

static PyObject *kshake320_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = (char*)PyMem_Malloc(40);

#if PY_MAJOR_VERSION >= 3
    KSHAKE320POW((char *)PyBytes_AsString((PyObject*) input), output);
#else
    KSHAKE320POW((char *)PyString_AsString((PyObject*) input), output);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 40);
#else
    value = Py_BuildValue("s#", output, 40);
#endif
    PyMem_Free(output);
    return value;
}

static PyObject *kshake320_gethash320(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = (char*)PyMem_Malloc(40);

#if PY_MAJOR_VERSION >= 3
    GetHash320((char *)PyBytes_AsString((PyObject*) input), Py_SIZE((PyObject*) input), output);
#else
    GetHash320((char *)PyString_AsString((PyObject*) input), Py_SIZE((PyObject*) input), output);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 40);
#else
    value = Py_BuildValue("s#", output, 40);
#endif
    PyMem_Free(output);
    return value;
}

static PyObject *kshake320_gethash256(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = (char*)PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    GetHash256((char *)PyBytes_AsString((PyObject*) input), Py_SIZE((PyObject*) input), output);
#else
    GetHash256((char *)PyString_AsString((PyObject*) input), Py_SIZE((PyObject*) input), output);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef KSHAKE320Methods[] = {
    { "getPoWHash", kshake320_getpowhash, METH_VARARGS, "Returns the kshake320 pow hash" },
    { "getHash320", kshake320_gethash320, METH_VARARGS, "Returns the kshake320 hash 320" },
    { "getHash256", kshake320_gethash256, METH_VARARGS, "Returns the kshake320 hash 256" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef KSHAKE320Module = {
    PyModuleDef_HEAD_INIT,
    "kshake320_hash",
    "...",
    -1,
    KSHAKE320Methods
};

PyMODINIT_FUNC PyInit_kshake320_hash(void) {
    return PyModule_Create(&KSHAKE320Module);
}

#else

PyMODINIT_FUNC initkshake320_hash(void) {
    (void) Py_InitModule("kshake320_hash", KSHAKE320Methods);
}
#endif
