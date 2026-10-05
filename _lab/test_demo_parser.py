"""Pruebas del parser de ping de la demo, sin necesidad de VMs.

Se ejecutan con:  python _lab\test_demo_parser.py

Por que existen: la demo annot cada paquete con el instante en que se EMITIA la
linea, no en que LLEGABA. Como el parser retiene la ultima linea de cada trozo
para no emitir un paquete a medias, con 'interval=1' eso retrasaba todos los
sellos ~1 s. Un paquete enviado justo antes del bloqueo se anotaba despues, ya
dentro de la etapa BLOQUEADO, y el veredicto 'dejo de llegar' fallaba por un
artefacto de reloj. Estas pruebas fijan el comportamiento correcto: el sello debe
ser el de llegada.

Tambien cubren un fallo que costo una corrida: el metodo que limpia los trozos
consumidos estaba definido como '_cursor_limpido' y se llamaba '_cursor_limpio'.
Python no avisa de eso al compilar; solo falla en runtime, los dos hilos de ping
mueren en el primer trozo y la demo se queda en 0/0 paquetes.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import demo_bloqueo as demo  # noqa: E402


def _linea(seq, ok=True):
    """Linea de /ping de RouterOS tal cual la emite el equipo."""
    if ok:
        return '    %d 10.10.1.3     56  63 465us     \r\n' % seq
    # En los timeouts RouterOS omite SIZE y TTL y deja el hueco.
    return '    %d 10.10.1.3                    timeout     \r\n' % seq


class _Reloj:
    """Reloj controlado: cada trozo 'llega' cuando se le dice."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TestSelloDePaquetes(unittest.TestCase):

    def setUp(self):
        self.reloj = _Reloj()
        self._ts_real = demo._ts
        demo._ts = self.reloj
        self.p = demo.PingContinuo('10.10.1.3', 'atacante->victima', mostrar=False)

    def tearDown(self):
        demo._ts = self._ts_real

    def _alimentar(self, n, intervalo=1.0, ok=True):
        for i in range(n):
            self.reloj.t = i * intervalo
            self.p._procesar(_linea(i, ok))
        self.reloj.t = n * intervalo
        self.p._procesar('', final=True)

    def test_el_sello_es_el_de_llegada_y_no_el_de_emision(self):
        """El bug central: con el retenido, emitir un intervalo mas tarde."""
        self._alimentar(5)
        self.assertEqual(len(self.p.paquetes), 5)
        for t, seq, _ok, _rtt in self.p.paquetes:
            self.assertAlmostEqual(
                t, seq * 1.0, places=6,
                msg='el paquete %d se sello en %.2f pero llegó en %.2f'
                    % (seq, t, seq * 1.0))

    def test_los_trozos_se_limpian(self):
        """La lista de trozos no puede crecer durante toda la demo."""
        self._alimentar(40)
        self.assertLessEqual(
            len(self.p._trozos), 3,
            'los trozos consumidos se acumulan: %d vivos' % len(self.p._trozos))

    def test_retene_la_ultima_linea_a_medias(self):
        """El retenido es necesario: una linea partida no se debe emitir."""
        self.reloj.t = 0.0
        completa = _linea(0)
        self.p._procesar(completa[:20])          # mitad de la linea
        self.assertEqual(self.p.paquetes, [], 'emitio una linea a medias')
        self.p._procesar(completa[20:])          # resto
        self.assertEqual(len(self.p.paquetes), 0,
                         'el retenido no debe adelantarse: la linea estaba completa')
        self.reloj.t = 1.0
        self.p._procesar(_linea(1))
        self.assertEqual(len(self.p.paquetes), 1)
        self.assertEqual(self.p.paquetes[0][1], 0)

    def test_reconoce_timeouts(self):
        """RouterOS omite SIZE y TTL en los timeouts: si se exigian, no casaban."""
        self._alimentar(3, ok=False)
        self.assertEqual(len(self.p.paquetes), 3)
        self.assertTrue(all(not ok for _t, _s, ok, _r in self.p.paquetes))
        self.assertTrue(all(rtt is None for _t, _s, _o, rtt in self.p.paquetes))

    def test_mezcla_ok_y_timeout(self):
        """El parser tiene que seguir contando los paquetes amid-stream."""
        self.reloj.t = 0.0
        self.p._procesar(_linea(0, ok=True))
        self.reloj.t = 1.0
        self.p._procesar(_linea(1, ok=False))
        self.reloj.t = 2.0
        self.p._procesar(_linea(2, ok=True))
        self.reloj.t = 3.0
        self.p._procesar('', final=True)
        self.assertEqual([ok for _t, _s, ok, _r in self.p.paquetes],
                         [True, False, True])

    def test_trozos_entregados_juntos(self):
        """Varios paquetes en un solo trozo: cada uno con SU hora de llegada."""
        self.reloj.t = 5.0
        self.p._procesar(_linea(0) + _linea(1) + _linea(2))
        self.reloj.t = 6.0
        self.p._procesar('', final=True)
        self.assertEqual(len(self.p.paquetes), 3)
        # Los tres llegaron en el mismo trozo, asi que los tres comparten reloj.
        for t, _seq, _ok, _rtt in self.p.paquetes:
            self.assertAlmostEqual(t, 5.0, places=6)


class TestNombresDeMetodos(unittest.TestCase):
    """El fallo que dejo la demo en 0/0: una errata que py_compile no detecta."""

    def test_el_metodo_de_limpieza_existe_con_su_nombre_exacto(self):
        self.assertTrue(
            hasattr(demo.PingContinuo, '_cursor_limpido'),
            "PingContinuo no tiene _cursor_limpido; se llama de otra forma "
            "y el runtime falla con AttributeError")

    def test_no_hay_grafias_parecidas_del_mismo_metodo(self):
        """Dos nombres que se parecen son un bug esperando a ocurrir."""
        import re
        with open(demo.__file__, encoding='utf-8-sig') as fh:
            src = fh.read()
        nombres = set(re.findall(r'_cursor_limp\w*', src))
        self.assertEqual(
            len(nombres), 1,
            'conviven %d grafias distintas: %s' % (len(nombres), nombres))


if __name__ == '__main__':
    unittest.main(verbosity=2)
