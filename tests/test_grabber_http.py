# -*- coding: utf-8 -*-
"""
test_grabber_http.py — Grabber HTTP benigno UNIPAZ (M2) sin scapy ni red.

Prueba: parser de peticiones, sanitización (regla de _sanear_muestra_sqli),
persistencia incremental, REANUDACIÓN tras "apagón" (cerrar y reabrir la BD
conserva el conteo) y truncados de privacidad.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from scripts.grabber_http_benigno import GrabberHTTP, _RE_PETICION  # noqa: E402


@pytest.fixture()
def grabber(tmp_path):
    g = GrabberHTTP(bd_path=tmp_path / 'captura.db')
    yield g
    g.con.close()


def _peticion(method='GET', ruta='/index.html', host='portal.unipaz.edu',
              cuerpo='', extra_headers=''):
    texto = f'{method} {ruta} HTTP/1.1\r\nHost: {host}\r\n{extra_headers}\r\n{cuerpo}'
    return texto.encode('ascii')


def test_parser_reconoce_peticion(grabber):
    p = grabber._parsear(_peticion('POST', '/login', cuerpo='user=a&pass=b'))
    assert p['metodo'] == 'POST'
    assert p['ruta'] == '/login'
    assert p['host'] == 'portal.unipaz.edu'
    assert p['cuerpo'] == 'user=a&pass=b'


def test_parser_descarta_respuestas(grabber):
    assert grabber._parsear(b'HTTP/1.1 200 OK\r\n\r\nhola') is None
    assert grabber._parsear(b'\x00\x01basura no ascii') is None
    assert grabber._parsear(b'') is None
    assert grabber._parsear(b'x' * 9000) is None  # demasiado grande


def test_sanitizacion_credenciales(grabber):
    p = grabber._parsear(_peticion('POST', '/login', cuerpo='usuario=a&password=secreto123'))
    assert 'secreto123' not in p['cuerpo']
    assert 'omitido' in p['cuerpo']


def test_ruta_con_sesion_sin_query(grabber):
    p = grabber._parsear(_peticion('GET', '/panel?id=7&session=abc123'))
    assert 'session=abc123' not in p['ruta']
    assert p['ruta'] == '/panel'


def test_persistencia_y_reanudacion(tmp_path):
    """El caso del apagon: cerrar la BD y reabrirla conserva el conteo."""
    bd = tmp_path / 'captura.db'
    g1 = GrabberHTTP(bd_path=bd)
    g1._cola.append(('2026-11-04T12:00:00+00:00', '172.10.x.x', 80,
                     'GET', 'a.unipaz.edu', '/inicio', '', 100))
    g1._flush()
    g1.cerrar()  # "apagon" ordenado

    g2 = GrabberHTTP(bd_path=bd)  # reanuda
    assert g2.total == 1, 'el conteo acumulado debe sobrevivir al apagon'
    n = g2.con.execute('SELECT COUNT(*) FROM peticiones').fetchone()[0]
    assert n == 1

    g2._cola.append(('2026-11-04T12:01:00+00:00', '172.10.x.x', 80,
                     'GET', 'a.unipaz.edu', '/otra', '', 90))
    g2._flush()
    g2.cerrar()
    g3 = GrabberHTTP(bd_path=bd)
    assert g3.total == 2
    g3.con.close()


def test_truncados_privacidad(grabber):
    assert grabber._truncar_ip('172.10.5.185') == '172.10.x.x'
    ruta_larga = '/' + 'a' * 900
    p = grabber._parsear(_peticion('GET', ruta_larga))
    assert len(p['ruta']) == 500


def test_regex_acepta_metodos_reales():
    for metodo in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
        assert _RE_PETICION.match(f'{metodo} /x HTTP/1.1')
    assert _RE_PETICION.match('CONNECT evil.com HTTP/1.1') is None
    assert _RE_PETICION.match('HTTP/1.1 200 OK') is None


def test_informe_contiene_total(grabber):
    grabber._cola.append(('2026-11-04T12:00:00+00:00', '172.10.x.x', 80,
                          'GET', 'a', '/', '', 50))
    grabber._flush()
    assert 'total=1' in grabber.informe()
