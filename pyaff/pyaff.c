/******************************************************
 * Copyright 2008: David Collett <david.collett@gmail.com> 
 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * (LGPL) as published by the Free Software Foundation; either version
 * 3 of the License as of 29 June 2007, or (at your option) any later
 * version.
 *
 * See http://www.gnu.org/licenses/lgpl.txt
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details. 
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02
 * -1307, USA. 
 ****************************************************/

#include "Python.h"
#include "lib/afflib.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/******************************************************************
 * pyaff - afflib python binding
 * ***************************************************************/

typedef struct {
    PyObject_HEAD
    AFFILE *af;
    uint64_t size;
} affile;

static void affile_dealloc(affile *self);
static int affile_init(affile *self, PyObject *args, PyObject *kwds);
static PyObject *affile_read(affile *self, PyObject *args, PyObject *kwds);
static PyObject *affile_seek(affile *self, PyObject *args, PyObject *kwds);
static PyObject *affile_get_seg(affile *self, PyObject *args, PyObject *kwds);
static PyObject *affile_get_seg_names(affile *self);
static PyObject *affile_tell(affile *self);
static PyObject *affile_close(affile *self);

static PyMethodDef affile_methods[] = {
    {"read", (PyCFunction)affile_read, METH_VARARGS|METH_KEYWORDS,
     "Read data from file" },
    {"seek", (PyCFunction)affile_seek, METH_VARARGS|METH_KEYWORDS,
     "Seek within a file" },
    {"get_seg", (PyCFunction)affile_get_seg, METH_VARARGS|METH_KEYWORDS,
     "Retrieve an aff segment by name" },
    {"get_seg_names", (PyCFunction)affile_get_seg_names, METH_NOARGS,
     "Retrieve a list of segments present" },
    {"tell", (PyCFunction)affile_tell, METH_NOARGS,
     "Return possition within file" },
    {"close", (PyCFunction)affile_close, METH_NOARGS,
     "Close the file" },
    {NULL}  /* Sentinel */
};

static PyTypeObject affileType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pyaff.affile",            /* tp_name */
    sizeof(affile),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)affile_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "afflib File Object",      /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    affile_methods,            /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)affile_init,     /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static void
affile_dealloc(affile *self) {
    self->ob_type->tp_free((PyObject*)self);
}

static int
affile_init(affile *self, PyObject *args, PyObject *kwds) {
	char *filename;
    static char *kwlist[] = {"filename", NULL};

    self->size = 0;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &filename))
        return -1;

    self->af = af_open(filename, O_RDONLY, 0);
    if(self->af == NULL) {
    	PyErr_Format(PyExc_IOError, "Failed to initialise afflib");
    	return -1;
    }

    self->size = af_get_imagesize(self->af);
    return 0;
}

static PyObject *
affile_read(affile *self, PyObject *args, PyObject *kwds) {
    int written;
    PyObject *retdata;
    int readlen=-1;

    static char *kwlist[] = {"size", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &readlen))
        return NULL; 

    if(readlen < 0 || readlen > self->size)
    	readlen = self->size;

    retdata = PyString_FromStringAndSize(NULL, readlen);
    written = af_read(self->af, (unsigned char *)PyString_AsString(retdata), readlen);

    if(readlen != written) {
        return PyErr_Format(PyExc_IOError, "Failed to read all data: wanted %d, got %d", readlen, written);
    }

    return retdata;
}

static PyObject *
affile_seek(affile *self, PyObject *args, PyObject *kwds) {
    int64_t offset=0;
    int whence=0;

    static char *kwlist[] = {"offset", "whence", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "L|i", kwlist, 
                                    &offset, &whence))
        return NULL; 

    if(af_seek(self->af, offset, whence) < 0)
        return PyErr_Format(PyExc_IOError, "libaff_seek_offset failed");

    Py_RETURN_NONE;
}

static PyObject *
affile_tell(affile *self) {
    return PyLong_FromLongLong(af_tell(self->af));
}

static PyObject *
affile_close(affile *self) {
  af_close(self->af);
  Py_RETURN_NONE;
}

static PyObject *affile_get_seg(affile *self, PyObject *args, PyObject *kwds) {
	PyObject *retdata;
	char *buf;
	size_t buflen=0;
	char *segname=NULL;
    static char *kwlist[] = {"segname", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &segname))
        return NULL;

    // first get the size
    if(af_get_seg(self->af, segname, 0, 0, &buflen) != 0) {
        return PyErr_Format(PyExc_IOError, "error reading libaff segment\n");
    }
    
    // allocate a string to return data in
    retdata = PyString_FromStringAndSize(NULL, buflen);
    buf = PyString_AsString(retdata);

    if(af_get_seg(self->af, segname, 0, (unsigned char *)buf, &buflen) != 0) {
        Py_DECREF(retdata);
        return PyErr_Format(PyExc_IOError, "error reading libaff segment\n");
    }
 
    return retdata;
}

static PyObject *affile_get_seg_names(affile *self) {
	PyObject *headers, *tmp;
	char segname[AF_MAX_NAME_LEN];

    af_rewind_seg(self->af);
    headers = PyList_New(0);

    while(af_get_next_seg(self->af, segname, sizeof(segname), 0, 0, 0) == 0){
        tmp = PyString_FromString(segname);
        PyList_Append(headers, tmp);
        Py_DECREF(tmp);
    }

    return headers;
}

static PyObject *pyaff_open(PyObject *self, PyObject *args, PyObject *kwds) {
	int ret;
	affile *file;
	PyObject *files, *fileargs, *filekwds;
    static char *kwlist[] = {"filename", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &files))
        return NULL;

    /* create an affile object and return it */
    fileargs = PyTuple_New(0);
    filekwds = Py_BuildValue("{sO}", "filename", files);
    if(!filekwds) return NULL;

    file = PyObject_New(affile, &affileType);
    ret = affile_init(file, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);

    if(ret == -1) {
        Py_DECREF(file);
        return NULL;
    }
    return (PyObject *)file;
}

/* these are the module methods */
static PyMethodDef pyaff_methods[] = {
    {"open", (PyCFunction)pyaff_open, METH_VARARGS|METH_KEYWORDS,
     "Open afflib file (or set of files)" },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initpyaff(void) 
{
    PyObject* m;

    /* create module */
    m = Py_InitModule3("pyaff", pyaff_methods, "Python libaff module.");

    /* setup affile type */
    affileType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&affileType) < 0)
        return;

    Py_INCREF(&affileType);
    PyModule_AddObject(m, "affile", (PyObject *)&affileType);
}

