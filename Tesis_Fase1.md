# Información de la Tesis — Fase 1

> **IMPLEMENTACIÓN DE UN SISTEMA DE DETECCIÓN DE INTRUSIONES CIBERNÉTICAS BASADO EN MACHINE LEARNING PARA LA RED INSTITUCIONAL DEL INSTITUTO UNIVERSITARIO DE LA PAZ**

---

## Portada

**Título:** IMPLEMENTACIÓN DE UN SISTEMA DE DETECCIÓN DE INTRUSIONES CIBERNÉTICAS BASADO EN MACHINE LEARNING PARA LA RED INSTITUCIONAL DEL INSTITUTO UNIVERSITARIO DE LA PAZ

**Autores:**
- JHONATAN DAVID SÁNCHEZ BALDOVINO
- LUISA FERNANDA ARIAS DE LA TORRE

**Trabajo:** ANTEPROYECTO PARA OPTAR POR EL TÍTULO DE INGENIERO INFORMÁTICO

**Director:** Ing. Esp. JHONIS RIOS MÚNERA
**Codirector:** Lic. Esp. DANIEL POSE

**Nota de Aceptación:**
- Presidente del Jurado
- Jurado
- Jurado

**Barrancabermeja, Marzo 2026**

---

## AGRADECIMIENTOS

### Luisa Fernanda Arias de la Torre

Agradezco profundamente a mis padres, Lida de la Torre y Marlon Arias, por su amor incondicional, por impulsarme a cumplir mis metas y, sobre todo, por nunca rendirse conmigo, incluso en los momentos más oscuros. Gracias por enseñarme, con su ejemplo, el valor de la constancia, la disciplina y los sueños, y por ser mi fuerza y mi refugio cuando más los he necesitado. Este logro es tanto mío como suyo, porque sin ustedes nada de esto hubiera sido posible.

A mi tía Diana Ortegón, gracias por orientarme con tanta paciencia en la elección de mi carrera y por acompañarme en cada paso de este camino, respondiendo cada una de mis preguntas y brindándome siempre su apoyo y sabiduría. A mi hermana Lina Arias, por su apoyo incondicional, por estar siempre dispuesta a tenderme la mano y, sobre todo, por regalarme sonrisas y carcajadas aun en mis momentos más difíciles, recordándome que siempre hay motivos para seguir adelante.

Extiendo un agradecimiento muy especial a mis abuelos, Gladys Díaz y Miguel Ortegón, por abrirme las puertas de su hogar y su corazón, por brindarme su amor, su cuidado y por convertirse en un pilar fundamental durante este proceso académico. Gracias por cada palabra de aliento y por enseñarme, con su ejemplo, la importancia de la familia y la unión.

Agradezco también a todos los docentes que han hecho parte de mi formación como profesional, por compartir generosamente sus conocimientos, por sus valiosas enseñanzas dentro y fuera del aula. De manera especial, extiendo mi agradecimiento al profesor Jhonis Ríos, mi director, por brindarnos la oportunidad de iniciar y desarrollar este proyecto, por su guía constante, su paciencia y por impulsarnos a crecer no solo como profesionales, sino también como seres humanos comprometidos y responsables.

Quiero agradecer a mis compañeros de clase, con quienes compartí no solo aprendizajes académicos, sino también momentos valiosos que hicieron de cada clase una experiencia única. Disfruté ver cómo crecimos juntos, cómo nos apoyamos mutuamente. En especial, quiero reconocer a mi compañero Mateo Jiménez, por ser un apoyo constante, por orientarnos siempre que lo necesitamos y por ayudarnos a superar cada obstáculo, especialmente en programación. Su disposición y compañerismo marcaron una gran diferencia en este camino.

Y, por último, quiero agradecer a mi compañero de proyecto, Jhonatan Sánchez, por ser más que un colega, un amigo confiable. Gracias por compartir largas horas de trabajo, ideas, aprendizajes, risas, desvelos y pequeños triunfos.

### Jhonatan David Sánchez Baldovino

Quiero dedicar unas palabras de agradecimiento, primero, a mi papá, Heriberto Antonio Barranco Sánchez, por estar pendiente de mí sin importar las circunstancias, por sus esfuerzos silenciosos y por su compañía constante, incluso cuando las cosas se pusieron difíciles en estos dos últimos años. Gracias por su apoyo incondicional, por darme fuerzas cuando pensé que no podía más y por demostrarme, con hechos, que siempre puedo contar con él.

A mi mamá, Anyelith Baldovino Machado, por sus consejos sinceros, por preocuparse por mí aun cuando no siempre supe escucharla, y por recordarme cada día que nunca estoy solo. Gracias por ser mi voz de aliento cuando más la necesité.

Agradezco de manera especial al profesor Jhonis Ríos, por la confianza que depositó en nosotros para realizar este proyecto, por su guía paciente y por su apoyo para crecer como profesional y como persona.

A Mateo Jiménez, por ser un compañero de clase invaluable, por su apoyo incondicional, por ayudarnos a resolver problemas cuando más lo necesitábamos y por demostrar siempre una disposición admirable para salir adelante juntos.

A mi compañera de proyecto de grado y gran amiga, Luisa, porque la quiero, porque estuvo ahí desde el inicio, ayudándome a sacar adelante este trabajo cuando las cosas se complicaban. Gracias por aportar sus ideas, por la paciencia y por hacer que todo fuera más llevadero, incluso en los días más pesados.

---

## CONTENIDO

| Sección | Pág. |
|---|---|
| INTRODUCCIÓN | 14 |
| 1. OBJETIVOS | 16 |
| 1.1 OBJETIVO GENERAL | 16 |
| 1.2 OBJETIVOS ESPECÍFICOS | 16 |
| 2. PLANTEAMIENTO DEL PROBLEMA | 17 |
| 2.1 DEFINICIÓN DEL PROBLEMA | 17 |
| 2.2 JUSTIFICACIÓN | 18 |
| 3. MARCO REFERENCIAL | 20 |
| 3.1 ANTECEDENTES | 20 |
| 3.2 MARCO TEÓRICO | 21 |
| 3.3 MARCO CONCEPTUAL | 25 |
| 3.4 MARCO LEGAL | 25 |
| 4. MATERIALES Y MÉTODOS | 27 |
| 4.1 MATERIALES | 27 |
| 4.2 METODOLOGÍA | 28 |
| 5. DESARROLLO DEL PROYECTO | 31 |
| 5.1 PLANIFICACIÓN DEL PROYECTO | 31 |
| 5.2 DIAGNÓSTICO DE SEGURIDAD DE LA RED | 36 |
| 5.3 DISEÑO DE LA ARQUITECTURA DEL IDS | 45 |
| 5.4 IMPLEMENTACIÓN DEL SISTEMA | 52 |
| 5.5 CONSTRUCCIÓN DEL DATASET | 52 |
| 5.6 ENTRENAMIENTO DEL MODELO DE MACHINE LEARNING | 53 |
| 5.7 PRUEBAS DE ATAQUE CONTROLADAS | 55 |
| 5.8 EVALUACIÓN DEL DESEMPEÑO | 58 |
| 6. CONCLUSIONES | 63 |
| 7. RECOMENDACIONES | 65 |
| BIBLIOGRAFÍA | 66 |

---

## LISTA DE TABLAS

| Pág. | Tabla |
|---|---|
| 31 | Tabla 1. Cronograma de actividades del proyecto |
| 43 | Tabla 2. Análisis cualitativo de la pregunta abierta |
| 54 | Tabla 3. Matriz de confusión para clasificación de tráfico |
| 58 | Tabla 4. Comparación entre tráfico de red y capacidad del IDS |
| 58 | Tabla 5. Resultados de pruebas de ataque SYN Flood |
| 59 | Tabla 6. Resultados de pruebas de ataque DoS |
| 60 | Tabla 7. Resultados de pruebas de ataque DDoS |
| 61 | Tabla 8. Resultados de pruebas de ataque Port Scan |

---

## LISTA DE FIGURAS

| Pág. | Figura |
|---|---|
| 19 | Figura 1. Diagrama de Ishikawa |
| 22 | Figura 2. Diagrama de red NIDS |
| 22 | Figura 3. Diagrama de red HIDS |
| 23 | Figura 4. Diagrama funcional de IDS Híbrido |
| 23 | Figura 5. Diagrama funcional de signature-based |
| 24 | Figura 6. Diagrama funcional de anomaly-based |
| 27 | Figura 7. Fotografía de materiales |
| 28 | Figura 8. Resumen visual de la metodología aplicada en el proyecto |
| 34 | Figura 9. Diagrama de gantt cronograma IDS |
| 35 | Figura 10. Tablero Kanban utilizado para la gestión del proyecto |
| 36 | Figura 11. Diagrama de red UNIPAZ |
| 37 | Figura 12. Registro de eventos del firewall institucional |
| 38 | Figura 13. Nivel de conocimiento sobre phishing entre los encuestados |
| 38 | Figura 14. Frecuencia de verificación de seguridad web |
| 39 | Figura 15. Conocimiento sobre sistemas de detección de intrusiones (IDS) |
| 39 | Figura 16. Frecuencia de cambio de contraseñas institucionales |
| 40 | Figura 17. Uso de contraseñas seguras entre los participantes |
| 40 | Figura 18. Verificación de enlaces y archivos antes de abrir correos |
| 41 | Figura 19. Frecuencia de actualización del sistema operativo y software |
| 41 | Figura 20. Conocimiento de seguridad informática institucional |
| 42 | Figura 21. Participación en capacitación en ciberseguridad |
| 46 | Figura 22. Arquitectura y flujo operativo del IDS |
| 47 | Figura 23. Función central de manejo de eventos de ataque |
| 47 | Figura 24. Control de frecuencia de alertas en el sistema IDS |
| 48 | Figura 25. Diagrama de flujo de un sistema IDS |
| 49 | Figura 26. Funcionamiento general de Scapy |
| 49 | Figura 27. Vista de la base de datos ataques_detectados.db |
| 50 | Figura 28. Captura de tráfico de red en Wireshark para la red UNIPAZ |
| 50 | Figura 29. Ejecución de ataque de tipo SYN Flood con Metasploit |
| 51 | Figura 30. Primer diseño de la interfaz IDS |
| 51 | Figura 31. Ultimo diseño de la interfaz IDS |
| 52 | Figura 32. Diagrama caso de uso interfaz de usuario IDS |
| 53 | Figura 33. Dataset generado a partir de simulaciones |
| 54 | Figura 34. Matriz de Confusión IDS |
| 56 | Figura 35. Captura de red con Wireshark en la red Administrativos |
| 56 | Figura 36. Captura de red con Wireshark en la red Estudiantes |
| 57 | Figura 37. Panel de Wireshark Statistic en la red Administrativos |
| 57 | Figura 38. Panel de Wireshark Statistic en la red Estudiante |
| 62 | Figura 39. Captura 2 de Notificación Telegram - Ataque en Curso |

---

## GLOSARIO

- **ALERTA:** notificación automática generada cuando el sistema detecta una posible intrusión.
- **ANOMALÍA:** comportamiento o patrón de tráfico que se desvía de lo considerado normal en la red y que puede indicar una amenaza.
- **API (Interfaz de Programación de Aplicaciones):** conjunto de funciones y protocolos que permiten la comunicación entre diferentes programas o servicios.
- **ATAQUE DE DÍA CERO:** vulnerabilidad desconocida por los fabricantes y aún sin parche, explotada por atacantes antes de que exista una solución.
- **BASE DE DATOS:** conjunto de datos o información almacenada para su consulta, análisis y gestión.
- **BOTNET:** red de equipos infectados controlados de manera remota por un atacante para ejecutar acciones maliciosas coordinadas.
- **CIBERATAQUES:** acciones maliciosas que potencialmente pueden dañar, vulnerar y/o robar información de sistemas, redes o datos.
- **CIBERSEGURIDAD:** prácticas, tecnologías y medidas diseñadas para resguardar sistemas, redes y datos frente a intrusiones.
- **CONSOLA DE GESTIÓN:** interfaz gráfica que permite a los administradores visualizar y gestionar alertas, reportes y configuraciones del sistema de detección de intrusiones.
- **DATASET:** conjunto de datos recogidos y organizados para entrenar y probar modelos de Machine Learning.
- **FALSO POSITIVO:** situación en la que el sistema de detección de intrusiones genera una alerta de intrusión cuando en realidad no existe amenaza.
- **FIREWALL:** sistema que filtra y controla el tráfico de red autorizado o bloqueado según políticas de seguridad establecidas.
- **INTERFAZ GRÁFICA DE USUARIO (GUI):** elemento visual de un software que permite al usuario interactuar con el sistema mediante ventanas, botones y menús.
- **INTRUSIÓN:** acceso no autorizado a sistemas, redes o datos con fines de sabotaje, robo o alteración de información.
- **LOGS:** archivos donde se almacena de manera cronológica la actividad de la red, equipos y aplicaciones para fines de monitoreo y auditoría.
- **MACHINE LEARNING:** rama de la inteligencia artificial que desarrolla algoritmos capaces de aprender patrones a partir de datos y mejorar su desempeño sin intervención humana directa.
- **TASA DE DETECCIÓN:** proporción de intrusiones reales que son correctamente identificadas por el IDS respecto al total de intrusiones existentes.
- **TELEGRAM BOT:** programa automatizado que interactúa mediante la aplicación de mensajería Telegram para enviar alertas y recibir comandos.
- **SENSOR:** componente del sistema de detección de intrusiones encargado de capturar y monitorizar el tráfico de red y la actividad del sistema para su posterior análisis.

---

## RESUMEN

La creciente conectividad de red en las instituciones de educación superior ha aumentado la cantidad de ciberataques, lo cual requiere soluciones de seguridad más efectivas que los cortafuegos y antivirus tradicionales. Este proyecto propone implementar un Sistema de Detección de Intrusiones Cibernéticas basado en Machine Learning para notificar sobre las intrusiones en la red del Instituto Universitario de la Paz (UNIPAZ).

La investigación utilizó un enfoque mixto con métodos cuantitativos y cualitativos, esto incluyó el análisis de registros del firewall, encuestas a estudiantes y personal técnico, y simulaciones de ataques en un entorno controlado. El IDS (sistema de detección de intrusiones) fue desarrollado en Python, usando librerías como Scapy, Pandas, Scikit-learn, Joblib y SQLite3. También tiene una interfaz gráfica en PyQt5 y un bot de Telegram para enviar notificaciones en tiempo real.

El sistema se entrenó para detectar patrones inusuales en el tráfico que indican ataques como SYN Flood, DoS, DDoS, Port Scan e inyección SQL. Logrando una alta tasa de detección y menos falsos positivos en las pruebas. Los resultados muestran que un IDS con aprendizaje automático ayuda a responder más rápido a las amenazas nuevas y refuerza la seguridad informática y el funcionamiento continuo de UNIPAZ.

**PALABRAS CLAVE:** Ciberseguridad, Detección de intrusos, Machine Learning, Redes informáticas.

---

## INTRODUCCIÓN

La creciente dependencia de las instituciones de educación superior respecto a infraestructuras tecnológicas ha transformado la gestión académica y administrativa, pero también ha ampliado de manera significativa la superficie de exposición a amenazas cibernéticas. En Colombia, el incremento sostenido de incidentes de seguridad informática registrado por el Centro Cibernético Policial evidencia que las organizaciones públicas y privadas, incluyendo las instituciones educativas, se encuentran cada vez más expuestas a ataques dirigidos que comprometen la confidencialidad, integridad y disponibilidad de la información.

El Instituto Universitario de la Paz (UNIPAZ) no es ajeno a esta realidad. Su red institucional soporta servicios críticos como plataformas académicas, correo institucional, sistemas administrativos y almacenamiento de información sensible de estudiantes, docentes y personal administrativo. Sin embargo, los mecanismos de seguridad implementados actualmente, basados principalmente en firewalls y antivirus convencionales, presentan limitaciones frente a ataques sofisticados, anomalías de tráfico y amenazas de día cero. A esto se suma el elevado volumen de eventos de red generados diariamente, que dificulta su análisis manual e incrementa el riesgo de retrasos en la detección.

Ante este panorama, los Sistemas de Detección de Intrusiones basados en técnicas de Machine Learning emergen como una alternativa tecnológica viable para fortalecer la postura de ciberseguridad institucional. A diferencia de los sistemas tradicionales basados en firmas, los modelos de aprendizaje automático poseen la capacidad de identificar patrones anómalos en el tráfico de red, adaptarse a amenazas emergentes y generar alertas en tiempo real, lo que contribuye a una respuesta más oportuna ante incidentes de seguridad.

El presente proyecto describe la implementación de un Sistema de Detección de Intrusiones Cibernéticas basado en Machine Learning para la red institucional de UNIPAZ. El sistema fue desarrollado en Python, integrando librerías especializadas como Scapy, Pandas, Scikit-learn, Joblib y SQLite3, así como una interfaz gráfica construida en PyQt5 y un bot de Telegram para la gestión de notificaciones en tiempo real. La solución permite capturar, procesar y clasificar el tráfico de red, diferenciando entre comportamiento legítimo y eventos maliciosos asociados a ataques como SYN Flood, DoS, DDoS, Port Scan e inyección SQL.

Metodológicamente, el proyecto adoptó un enfoque mixto que combinó el análisis cuantitativo del tráfico de red con el análisis cualitativo de la percepción de la comunidad académica frente a la ciberseguridad. La investigación es de tipo aplicada, con un diseño no experimental de corte transversal, complementado con simulaciones controladas de ataques. El desarrollo del sistema se gestionó mediante la metodología ágil Kanban, garantizando la organización, seguimiento y control de las actividades asociadas al diseño, construcción y validación del IDS.

El documento se estructura de la siguiente manera: en primer lugar, se presentan los objetivos y el planteamiento del problema, que delimitan el alcance y la justificación del proyecto. A continuación, se expone el marco referencial, que abarca los antecedentes históricos de los IDS, el marco teórico sobre seguridad informática y Machine Learning, el marco conceptual y el marco legal aplicable. Posteriormente, se describen los materiales, la metodología y el desarrollo del proyecto, detallando las fases de diagnóstico, diseño, implementación, entrenamiento del modelo y evaluación del desempeño. Finalmente, se presentan las conclusiones y recomendaciones derivadas de los resultados obtenidos.

Los resultados obtenidos demuestran que el sistema alcanzó una tasa de detección del 100% en las pruebas de ataque controladas, con una tasa de falsos negativos del 0% y un tiempo de respuesta inferior a un segundo. Estos hallazgos confirman la viabilidad técnica de aplicar técnicas de inteligencia artificial en la protección de infraestructuras educativas y sientan las bases para futuras investigaciones en seguridad informática aplicada en el contexto institucional de UNIPAZ.

---

## 1. OBJETIVOS

### 1.1 OBJETIVO GENERAL

Implementar un sistema de detección de intrusiones cibernéticas basado en técnicas de Machine Learning en la red institucional del Instituto Universitario de la Paz, que permita identificar ataques informáticos y analizar su comportamiento mediante métricas de detección y tasa de error.

### 1.2 OBJETIVOS ESPECÍFICOS

- Identificar las principales vulnerabilidades y amenazas de seguridad presentes en la red institucional del INSTITUTO UNIVERSITARIO DE LA PAZ.
- Diseñar la arquitectura de un sistema de detección de intrusiones basado en Machine Learning para el análisis de tráfico de red.
- Aplicar el sistema IDS en un entorno de prueba controlado aplicando la metodología ágil Kanban para su desarrollo.
- Evaluar el desempeño del sistema mediante métricas de precisión, tasa de detección y análisis de falsos positivos y falsos negativos.

---

## 2. PLANTEAMIENTO DEL PROBLEMA

### 2.1 DEFINICIÓN DEL PROBLEMA

La modernización de las arquitecturas tecnológicas institucionales en la educación superior ha incrementado la dependencia de infraestructuras tecnológicas para la gestión académica y administrativa. Este escenario ha ampliado la superficie de exposición a amenazas cibernéticas, especialmente en entornos con alta conectividad y diversidad de dispositivos.

En Colombia, los incidentes de seguridad informática han presentado un crecimiento significativo. Reportes del Centro Cibernético Policial citados por LINKTIC¹ evidencian miles de ataques anuales dirigidos a organizaciones públicas y privadas, incluyendo instituciones educativas que gestionan información sensible de estudiantes, docentes y procesos administrativos.

En el Instituto Universitario de la Paz (UNIPAZ), la red institucional soporta servicios críticos como plataformas académicas, correo institucional, sistemas administrativos y almacenamiento de información. Sin embargo, los mecanismos de seguridad implementados actualmente, basados principalmente en firewalls y antivirus, presentan limitaciones frente a ataques sofisticados, anomalías de tráfico y amenazas de día cero.

Adicionalmente, el volumen de eventos de red generados diariamente dificulta su análisis manual, lo que incrementa el riesgo de falsos negativos², retrasos en la detección y posibles afectaciones a la confidencialidad, integridad y disponibilidad de la información institucional.

> **Pregunta problema:**
>
> ¿Cómo implementar un sistema de detección de intrusiones basado en técnicas de Machine Learning que permita identificar de manera temprana ataques cibernéticos en la red institucional de UNIPAZ y mejorar los niveles de detección frente a amenazas conocidas y desconocidas?

¹ LINKTIC. Panorama completo de la ciberseguridad en Colombia [en línea]. Bogotá: LinkTIC, 2025. [Citado 14 julio 2025]. Disponible en: https://linktic.com/blog/panorama-completo-de-la-ciberseguridad-en-colombia/

² MIJALKOVIC, Jovana; SPOGNARDI, Angelo. Reducción de la tasa de falsos negativos en sistemas de detección de intrusiones en redes basados en aprendizaje profundo. En: Algorithms. 2022. vol. 15, no. 8, p. 258. Disponible en: https://doi.org/10.3390/a15080258 Consultado: 20 marzo 2026.

### 2.2 JUSTIFICACIÓN

La seguridad de la información se ha consolidado como un factor estratégico en las instituciones de educación superior, debido al manejo de datos sensibles y a la operación continua de servicios digitales. En este contexto, la protección de la infraestructura tecnológica de UNIPAZ resulta prioritaria para garantizar la continuidad académica y administrativa.

Las universidades representan objetivos atractivos para los ciberdelincuentes debido a la cantidad de usuarios conectados, la diversidad de dispositivos y el valor de la información almacenada. Ataques como denegación de servicio, robo de credenciales, malware e intrusiones no autorizadas pueden afectar la disponibilidad de los servicios y comprometer la privacidad institucional.

La implementación de un Sistema de Detección de Intrusiones (IDS) basado en Machine Learning permite fortalecer los mecanismos de defensa tradicionales, mediante el análisis inteligente de patrones de tráfico y la detección de comportamientos anómalos en tiempo real. A diferencia de los sistemas basados únicamente en firmas, los modelos de aprendizaje automático poseen capacidad de adaptación frente a amenazas emergentes.

Desde el ámbito tecnológico, el proyecto aporta el diseño e implementación de un prototipo funcional capaz de capturar, procesar y clasificar tráfico de red, integrando técnicas de análisis de datos y entrenamiento de modelos predictivos; en el ámbito institucional, contribuye al fortalecimiento de la postura de ciberseguridad, permitiendo la detección temprana de incidentes y la generación de alertas automatizadas para la toma de decisiones; finalmente, desde el ámbito académico, el proyecto sirve como base para futuras investigaciones en seguridad informática aplicada, promoviendo el uso de inteligencia artificial en la protección de infraestructuras educativas.

*Figura 1. Diagrama de Ishikawa — Fuente: Autoría Propia.*

---

## 3. MARCO REFERENCIAL

### 3.1 ANTECEDENTES

Los IDS han evolucionado como respuesta a la necesidad de monitorear y proteger infraestructuras computacionales frente a accesos no autorizados. Uno de los primeros aportes conceptuales fue desarrollado por James P. Anderson en 1980, quien propuso la automatización de la supervisión de eventos de seguridad mediante el análisis de registros de auditoría para identificar comportamientos anómalos³.

Posteriormente, Dorothy Denning desarrolló el modelo IDES (Intrusion Detection Expert System), considerado uno de los primeros sistemas funcionales de detección de intrusiones en tiempo real⁴. Este modelo incorporó perfiles de comportamiento y reglas estadísticas para identificar actividades sospechosas en sistemas informáticos⁵.

Durante las décadas siguientes surgieron soluciones como NSM, MIDAS y herramientas basadas en análisis de tráfico de red, que sentaron las bases de los actuales sistemas NIDS⁶. En 1998, la aparición de Snort marcó un avance significativo al permitir la detección basada en firmas mediante inspección de paquetes en tiempo real.

En la actualidad, los IDS han evolucionado hacia enfoques híbridos que integran técnicas de análisis estadístico y algoritmos de Machine Learning, permitiendo detectar amenazas desconocidas mediante el reconocimiento de patrones anómalos en el tráfico de red⁷.

³ ANDERSON, J. P. Computer Security Threat Monitoring and Surveillance [en línea]. 26 de febrero de 1980. [Citado 7 noviembre 2025]. Disponible en: https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/ande80.pdf

⁴ DENNING, D. E. An Intrusion-Detection Model [en línea]. 1986. [Citado 7 noviembre 2025]. Disponible en: https://www.academia.edu/8674514/An_Intrusion_Detection_Model

⁵ DENNING, Dorothy E. An intrusion-detection model. En: IEEE Transactions on Software Engineering. Febrero, 1987. vol. SE-13, no. 2, p. 222-232.

⁶ GONZÁLEZ, David. IDS V1.01: Estudio sobre sistemas de detección de intrusos [en línea]. [Citado 7 noviembre 2025]. Disponible en: https://dgonzalez.net/papers/ids/ids_v1.0.pdf

⁷ IBRAHIM, Laheeb M.; TAHA, Dujan B.; MAHMOD, Mahmod S. A comparison study for intrusion database (KDD99, NSL-KDD) based on self organization map (SOM) artificial neural network. En: Journal of Engineering Science and Technology. 2013. vol. 8, no. 1, p. 107–119.

### 3.2 MARCO TEÓRICO

La seguridad informática comprende el conjunto de políticas, mecanismos y tecnologías orientadas a proteger los activos de información frente a amenazas que comprometan su confidencialidad, integridad y disponibilidad, principios conocidos como la tríada CID⁸.

En entornos institucionales, la protección de redes adquiere especial relevancia debido al volumen de usuarios, dispositivos y servicios conectados simultáneamente. Dentro de este contexto surgen los Sistemas de Detección de Intrusiones (IDS), definidos como herramientas capaces de monitorear y analizar eventos de red o de host con el fin de identificar actividades maliciosas.

Los sistemas de detección de intrusos (IDS) se clasifican en:

- **IDS NIDS (Network-based Intrusion Detection Systems):** Analizan tráfico de red en puntos estratégicos⁹.
  - *Figura 2. Diagrama de red NIDS — Fuente: Autoría Propia.*
- **IDS HIDS (Host-based Intrusion Detection System):** Monitorean actividad interna de equipos¹⁰.
  - *Figura 3. Diagrama de red HIDS — Fuente: Autoría Propia.*
- **IDS HÍBRIDO:** Integran ambos enfoques¹¹.
  - *Figura 4. Diagrama funcional de IDS Híbrido — Fuente: Autoría Propia.*

Según su método de detección, pueden ser:

- **IDS signature-based (basado en firmas):** Detectan ataques conocidos.
  - *Figura 5. Diagrama funcional de signature-based — Fuente: Autoría Propia.*
- **IDS anomaly-based (basado en anomalías):** Identifican desviaciones del comportamiento normal.
  - *Figura 6. Diagrama funcional de anomaly-based — Fuente: Autoría Propia.*

El enfoque basado en anomalías ha sido fortalecido mediante técnicas de Machine Learning, las cuales permiten entrenar modelos capaces de clasificar tráfico legítimo y malicioso a partir de datasets etiquetados¹².

Entre las métricas utilizadas para evaluar su desempeño se encuentran:

- Precisión
- Tasa de detección
- Recall
- Falsos positivos
- Falsos negativos

Estas métricas permiten validar la efectividad del sistema implementado, la evaluación integral de estas métricas es el estándar actual para validar la eficacia de un NIDS basado en aprendizaje automático¹³.

⁸ IBM. Seguridad informática. [En línea]. Disponible en: https://www.ibm.com/es-es/topics/it-security [Accedido: 19 de julio de 2025].

⁹ FORTINET. ¿Qué es un sistema de detección de intrusos (IDS)? [En línea]. Disponible en: https://www.fortinet.com/lat/resources/cyberglossary/intrusion-detection-system [Consulta: 17 de noviembre de 2025]

¹⁰ ibidem.

¹¹ Ibidem.

¹² RAMAIAH, Mangayarkarasi; VANMATHI, C.; KHAN, Mohammad Zubair; VANITHA; DEEPA, M. Un sistema eficiente de detección de intrusiones para combatir las ciberamenazas mediante un modelo de red neuronal profunda. En: ITB Journal of ICT Research and Applications. 2023. vol. 17, no. 3. Disponible en: https://doi.org/10.5614/itbj.ict.res.appl.2023.17.3.2 Consultado: 20 marzo 2026.

¹³ HAROON, Shahzad; HUSSAIN, Syed Sajjad. Evaluación integral del rendimiento de un sistema de detección de intrusiones en la red mediante un enfoque de aprendizaje automático. En: Journal of Information Security and Risk Communication. 2023. vol. 17, no. 1. Disponible en: https://doi.org/10.31645/jisrc-019-01 Consultado: 20 marzo 2026.

### 3.3 MARCO CONCEPTUAL

Para el desarrollo del proyecto se consideran los siguientes conceptos clave:

- **Intrusión:** Acceso no autorizado a sistemas o redes con intención maliciosa.
- **Anomalía:** Patrón de tráfico que se desvía del comportamiento normal.
- **Falso positivo:** Alerta generada sin existir amenaza real.
- **Falso negativo:** Intrusión no detectada por el sistema.
- **Tasa de detección:** Proporción de ataques correctamente identificados respecto al total de ataques.
- **Sensor IDS:** Componente encargado de capturar tráfico y eventos.
- **Motor de análisis:** Módulo que procesa la información mediante reglas o modelos de aprendizaje automático.
- **Sistema de alertas:** Mecanismo de notificación ante eventos sospechosos.

Estos elementos conforman la arquitectura funcional del IDS implementado.

### 3.4 MARCO LEGAL

La implementación de sistemas de detección de intrusiones en entornos institucionales debe alinearse con la normativa colombiana de protección de datos y seguridad de la información.

Entre las principales disposiciones se encuentran:

- Constitución Política de Colombia, Artículo 15: Hábeas Data.
- Ley 1581 de 2012: Protección de datos personales.
- Decreto 1377 de 2013: Reglamentación del tratamiento de datos.
- Ley 1273 de 2009: Delitos informáticos.
- CONPES 3701 de 2011: Política de seguridad digital.
- ISO/IEC 27001: Gestión de seguridad de la información.

Estas normativas establecen lineamientos para el tratamiento seguro de la información y respaldan la implementación de tecnologías orientadas a la prevención de incidentes cibernéticos.

---

## 4. MATERIALES Y MÉTODOS

### 4.1 MATERIALES

Para el desarrollo del proyecto se emplearon recursos tecnológicos y metodológicos orientados a la captura, análisis y procesamiento de tráfico de red para la detección de intrusiones.

#### 4.1.1 Hardware

- Equipo de cómputo de escritorio con capacidad de procesamiento para entrenamiento de modelos.
- Router TP-Link Archer AX55 para la configuración del entorno de pruebas.
- Sistema de respaldo eléctrico (UPS) para garantizar continuidad operativa.

*Figura 7. Fotografía de materiales — Fuente: Fotografía propia.*

#### 4.1.2 Software

- Python como lenguaje de desarrollo.
- Librerías: Scapy, Pandas, Scikit-learn, Joblib y SQLite3.
- Wireshark para captura de tráfico.
- Nmap para escaneo de puertos.
- Metasploit para simulación de ataques.
- PyQt5 para el desarrollo de la interfaz gráfica.

#### 4.1.3 Recursos de información

- Registros del firewall institucional.
- Dataset de tráfico generado en laboratorio.
- Encuestas aplicadas a usuarios de la red institucional.

### 4.2 METODOLOGÍA

*Figura 8. Resumen visual de la metodología aplicada en el proyecto — Fuente: Elaboración propia.*

#### 4.2.1 Enfoque de investigación

El proyecto se desarrolló bajo un enfoque mixto, integrando análisis cuantitativo del tráfico de red y análisis cualitativo de la percepción de los usuarios frente a la ciberseguridad institucional.

#### 4.2.2 Tipo de investigación

La investigación es de tipo aplicada, orientada a la solución de un problema específico mediante el diseño e implementación de un sistema funcional de detección de intrusiones.

#### 4.2.3 Diseño de investigación

Se adoptó un diseño no experimental de corte transversal, basado en la observación y análisis de eventos de red en un periodo determinado, complementado con simulaciones controladas de ataques.

#### 4.2.4 Fases metodológicas

**Recopilación de información**
- Análisis documental de IDS y Machine Learning.
- Revisión de datasets de intrusiones.
- Solicitud de registros del firewall institucional.

**Captura y generación de datos**
- Monitoreo de tráfico mediante Wireshark.
- Escaneo de red con Nmap.
- Simulación de ataques DoS, DDoS, SYN Flood y Port Scan.

**Construcción del dataset**
- Etiquetado de tráfico normal y malicioso.
- Normalización de variables (puertos, tamaño de paquetes).
- Almacenamiento en base de datos SQLite3.

**Entrenamiento del modelo**
- Implementación de algoritmos de Machine Learning.
- Alimentación del modelo con datos etiquetados.
- Ajuste de parámetros.

**Evaluación del sistema**

Se utilizaron métricas de desempeño como:
- Precisión
- Tasa de detección
- Falsos positivos
- Falsos negativos

#### 4.2.5 Instrumentos de recolección

Se emplearon dos tipos:

**Técnicos**
- Captura de tráfico.
- Registros de firewall.
- Escaneo de vulnerabilidades.

**Perceptuales:** Se aplicó una encuesta estructurada a 51 participantes entre estudiantes y docentes, mediante formulario digital, con preguntas tipo Likert y dicotómicas orientadas a medir:
- Conocimiento de ciberataques.
- Hábitos de seguridad.
- Uso de contraseñas.
- Actualizaciones de software.

**Gestión del proyecto**

El desarrollo se gestionó mediante metodología ágil Kanban, utilizando Jira para la planificación, seguimiento y control de tareas.

---

## 5. DESARROLLO DEL PROYECTO

### 5.1 PLANIFICACIÓN DEL PROYECTO

El desarrollo del sistema de detección de intrusiones se estructuró mediante la metodología ágil Kanban, permitiendo la organización de actividades en fases de planificación, ejecución, validación e implementación.

Las tareas fueron gestionadas mediante la herramienta Jira, facilitando el seguimiento del progreso y la priorización de actividades asociadas al diseño, desarrollo y pruebas del sistema IDS.

**Tabla 1. Cronograma de actividades del proyecto**

| Actividad | Fecha de inicio | Fecha de finalización | DÍAS |
|---|---|---|---|
| **Semana 1: Infraestructura y Entorno** | 10/02/2025 | 14/02/2025 | 5 |
| Recolección de datos infraestructura UNIPAZ | 10/02/2025 | 14/02/2025 | 5 |
| Configuración del entorno de trabajo (Hardware y Software) | 10/02/2025 | 11/02/2025 | 2 |
| Instalación de librerías necesarias | 12/02/2025 | 13/02/2025 | 2 |
| Creación de entorno virtual | 13/02/2025 | 14/02/2025 | 2 |
| **Semana 2: Conexión SQLite3 y Alertas** | 17/02/2025 | 21/02/2025 | 5 |
| Importar SQLite3 para conexión de base de datos | 17/02/2025 | 17/02/2025 | 1 |
| Conexión con la base de datos local | 17/02/2025 | 18/02/2025 | 2 |
| Verificación de funcionamiento de entorno configurado | 19/02/2025 | 19/02/2025 | 1 |
| Crear base de datos SQLite3 (alertas, registro de alertas, envío de alertas) | 19/02/2025 | 21/02/2025 | 3 |
| Definir variables de entorno de prueba | 19/02/2025 | 21/02/2025 | 3 |
| **Semana 3: Detección MAC** | 24/02/2025 | 28/02/2025 | 5 |
| Creación de scripts para detección de modelos de dispositivos mediante dirección MAC | 24/02/2025 | 24/02/2025 | 1 |
| Descargar base de datos OUI actualizada | 25/02/2025 | 25/02/2025 | 1 |
| Aplicar base de datos en el código | 25/02/2025 | 26/02/2025 | 2 |
| Ejecutar búsquedas de modelos de dispositivos | 26/02/2025 | 27/02/2025 | 2 |
| Validar precisión de detección | 27/02/2025 | 27/02/2025 | 1 |
| Verificar resultados de búsquedas de modelos de dispositivos | 27/02/2025 | 28/02/2025 | 2 |
| Documentar resultados iniciales | 28/02/2025 | 28/02/2025 | 1 |
| **Semana 4: Captura Tráfico y CSV** | 03/03/2025 | 07/03/2025 | 5 |
| Captura de tráfico de red para entrenamiento | 03/03/2025 | 03/03/2025 | 1 |
| Clasificación de tráfico malicioso | 03/03/2025 | 03/03/2025 | 1 |
| Guardar archivos capturados en formato CSV | 04/03/2025 | 05/03/2025 | 2 |
| Análisis inicial de datos capturados | 05/03/2025 | 05/03/2025 | 1 |
| Pruebas de detección con datos reales | 05/03/2025 | 07/03/2025 | 3 |
| Activar virtualización de BIOS | 06/03/2025 | 07/03/2025 | 2 |
| **Semana 5: Anomalías y Dataset** | 10/03/2025 | 14/03/2025 | 5 |
| Detección de anomalías en tráfico de red | 10/03/2025 | 11/03/2025 | 2 |
| Procesamiento de datos (normalización de puertos y tamaños de paquetes) | 11/03/2025 | 12/03/2025 | 2 |
| Análisis inicial de patrones de tráfico | 13/03/2025 | 14/03/2025 | 2 |
| Generación de dataset etiquetado | 13/03/2025 | 13/03/2025 | 1 |
| Evaluación de herramientas de análisis de tráfico | 14/03/2025 | 14/03/2025 | 1 |
| **Semana 6: Modelo ML Inicial** | 18/03/2025 | 21/03/2025 | 4 |
| Implementación de modelo de Machine Learning inicial | 18/03/2025 | 18/03/2025 | 1 |
| Entrenamiento del modelo con datos recopilados | 19/03/2025 | 20/03/2025 | 2 |
| Evaluación inicial del modelo entrenado | 20/03/2025 | 21/03/2025 | 2 |
| **Semana 7: Optimización y Métricas ML** | 24/03/2025 | 28/03/2025 | 5 |
| Instalación de bibliotecas necesarias para visualización: Scikit-learn, Pandas, NumPy, TensorFlow, Matplotlib | 24/03/2025 | 24/03/2025 | 1 |
| Evaluación del rendimiento del modelo de ML | 25/03/2025 | 26/03/2025 | 2 |
| Ajustes y optimización del modelo | 26/03/2025 | 26/03/2025 | 1 |
| Generación de reportes de efectividad | 27/03/2025 | 27/03/2025 | 1 |
| Pruebas con nuevos conjuntos de datos | 27/03/2025 | 28/03/2025 | 2 |
| Implementación de métricas de evaluación | 28/03/2025 | 28/03/2025 | 1 |
| **Semana 8: Wireframes y Dashboard** | 31/03/2025 | 04/04/2025 | 5 |
| Diseño inicial de interfaz gráfica (wireframes y prototipos) | 31/03/2025 | 01/04/2025 | 2 |
| Implementación de dashboard básico para visualizar detecciones | 01/04/2025 | 04/04/2025 | 4 |
| Implementación de gráficos interactivos | 02/04/2025 | 04/04/2025 | 3 |
| Pruebas de integración con primer filtro IDS | 03/04/2025 | 04/04/2025 | 2 |
| **Semana 9: Interfaz y Usabilidad** | 07/04/2025 | 11/04/2025 | 5 |
| Desarrollo de la interfaz gráfica con recomendaciones | 07/04/2025 | 11/04/2025 | 5 |
| Implementación de funcionalidad básica (conexión con detecciones y alertas) | 08/04/2025 | 09/04/2025 | 2 |
| Pruebas iniciales de usabilidad | 09/04/2025 | 09/04/2025 | 1 |
| Implementación de ajustes visuales | 10/04/2025 | 11/04/2025 | 2 |
| Evaluación de la experiencia del usuario | 10/04/2025 | 11/04/2025 | 2 |
| **Semana 10: Integración Interfaz + ML** | 14/04/2025 | 18/04/2025 | 5 |
| Integración de la interfaz con los resultados de Machine Learning | 14/04/2025 | 14/04/2025 | 1 |
| Pruebas de comunicación entre interfaz y base de datos | 14/04/2025 | 15/04/2025 | 2 |
| Depuración de errores visuales | 15/04/2025 | 17/04/2025 | 3 |
| Ajustes en la estructura de datos recibidos | 17/04/2025 | 18/04/2025 | 2 |
| Ajustes de reportes generados por la interfaz | 18/04/2025 | 18/04/2025 | 1 |
| **Semana 11: Refinamiento y Rendimiento** | 21/04/2025 | 25/04/2025 | 5 |
| Refinamiento de interfaz de usuario | 21/04/2025 | 22/04/2025 | 2 |
| Mejoras en visualización de alertas y predicciones | 23/04/2025 | 23/04/2025 | 1 |
| Implementación de reporte automatizado de alertas | 23/04/2025 | 25/04/2025 | 3 |
| Pruebas de rendimiento en entorno real | 24/04/2025 | 25/04/2025 | 2 |
| Evaluación del sistema por parte del equipo de pruebas | 25/04/2025 | 25/04/2025 | 1 |
| **Semana 12: Pruebas Metasploit** | 28/04/2025 | 02/05/2025 | 5 |
| Implementación de mejoras basadas en pruebas de usuario | 28/04/2025 | 29/04/2025 | 2 |
| Pruebas de ataques con Metasploit | 29/04/2025 | 30/04/2025 | 2 |
| Revisión general del sistema | 30/04/2025 | 02/05/2025 | 3 |
| **Semana 13: Pruebas en Redes UNIPAZ** | 05/05/2025 | 09/05/2025 | 5 |
| Pruebas de rendimiento del sistema en diferentes redes institucionales | 05/05/2025 | 06/05/2025 | 2 |
| Simulaciones de ataques y respuestas del sistema | 07/05/2025 | 08/05/2025 | 2 |
| Corrección de fallos detectados en pruebas | 08/05/2025 | 09/05/2025 | 2 |
| **Semana 14: Simulaciones de Ataques** | 12/05/2025 | 16/05/2025 | 5 |
| Simulaciones de ataques y respuestas del sistema | 12/05/2025 | 13/05/2025 | 4 |
| Corrección de fallos detectados en pruebas | 14/05/2025 | 14/05/2025 | 1 |
| Evaluación de seguridad del sistema | 15/05/2025 | 16/05/2025 | 2 |
| **Semana 15: Ajustes Docentes** | 19/05/2025 | 23/05/2025 | 5 |
| Optimización del rendimiento | 19/05/2025 | 20/05/2025 | 2 |
| Implementación de cambios sugeridos por los docentes | 20/05/2025 | 23/05/2025 | 4 |
| **Semana 16: Informe Final y Validación** | 26/05/2025 | 30/05/2025 | 5 |
| Simulación de uso del sistema en entorno controlado | 26/05/2025 | 27/05/2025 | 2 |
| Preparación de informe final | 27/05/2025 | 29/05/2025 | 3 |
| Validación final del modelo de Machine Learning | 29/05/2025 | 30/05/2025 | 2 |
| **Semana 17: Evaluación de Impacto** | 02/06/2025 | 06/06/2025 | 5 |
| Simulación de uso del sistema en entorno controlado | 02/06/2025 | 06/06/2025 | 5 |
| Evaluación de impacto del sistema | 03/06/2025 | 05/06/2025 | 3 |
| Evaluación del cumplimiento de objetivos | 06/06/2025 | 06/06/2025 | 1 |
| **Semana 18: Ajustes Retroalimentación** | 09/06/2025 | 13/06/2025 | 5 |
| Ajustes finales según retroalimentación | 09/06/2025 | 12/06/2025 | 4 |
| Simulación de uso del sistema en entorno controlado | 13/06/2025 | 13/06/2025 | 1 |
| **Semana 19: Entrega Oficial del Proyecto** | 16/06/2025 | 20/06/2025 | 5 |
| Entrega oficial del proyecto | 16/06/2025 | 18/06/2025 | 3 |
| Planificación de futuras mejoras | 20/06/2025 | 20/06/2025 | 1 |

Fuente: Elaboración propia.

*Figura 9. Diagrama de Gantt cronograma IDS — Fuente: Elaboración propia.*
*Figura 10. Tablero Kanban utilizado para la gestión del proyecto — Fuente: Elaboración propia.*

### 5.2 DIAGNÓSTICO DE SEGURIDAD DE LA RED

Se realizó un análisis del entorno tecnológico institucional, identificando los activos de red, servicios críticos y posibles vectores de ataque.

#### 5.2.1 Revisión de infraestructura LAN

*Figura 11. Diagrama de red UNIPAZ — Fuente: Elaboración propia.*

Los usuarios de la red son docentes, estudiantes, personal administrativo y técnico, estos acceden a diario a la infraestructura tecnológica del Instituto Universitario de la Paz.

#### 5.2.2 Análisis de registros del firewall

La información recopilada detecta patrones de ataque que muestran que la red está expuesta a amenazas externas. Estas amenazas incluyen intentos de explotar vulnerabilidades mediante scripts maliciosos, conexiones no autorizadas y tráfico automatizado asociado a malware.

*Figura 12. Registro de eventos del firewall institucional — Fuente: Departamento de TI del Instituto Universitario de la Paz, 2025.*

Los logs evidenciaron tráfico malicioso asociado a botnets, escaneo de puertos y solicitudes automatizadas de scripts remotos, confirmando la necesidad de mecanismos avanzados de detección.

#### 5.2.3 Análisis de la encuesta preguntas cerradas

Se aplicó un instrumento de recolección de datos tipo encuesta a una muestra de 51 integrantes (estudiantes y docentes) del programa de Ingeniería Informática de UNIPAZ. La herramienta, estructurada mediante Google Forms, incluyó ítems cerrados con escala Likert y un apartado cualitativo para sugerencias de optimización.

**Figura 13. Nivel de conocimiento sobre phishing entre los encuestados**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

Entre los 51 participantes el 70,6% identifica el concepto de phishing, mientras que el 29,4% restante posee un desconocimiento operativo sobre la amenaza. Esta brecha técnica confirma una vulnerabilidad crítica ante vectores de suplantación de identidad por carencia de formación institucional específica.

**Figura 14. Frecuencia de verificación de seguridad web**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

El 41,2% de los encuestados valida siempre el protocolo HTTPS; no obstante, el 58,8% restante omite esta práctica de forma total o parcial. Esta carencia de hábito preventivo eleva el riesgo de exposición ante sitios maliciosos y compromete la integridad de la red institucional.

**Figura 15. Conocimiento sobre sistemas de detección de intrusiones (IDS)**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

Solo el 41,2% de los participantes conoce el concepto de IDS, mientras que el 58,8% restante presenta desconocimiento parcial o total sobre la herramienta.

**Figura 16. Frecuencia de cambio de contraseñas institucionales**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

El 39,2% de los usuarios no realiza cambios de contraseña y el 51% lo hace con baja frecuencia. Solo el 17,6% de la muestra cumple con la actualización trimestral recomendada para entornos institucionales. Esta deficiencia en la rotación de credenciales incrementa la vulnerabilidad ante intrusiones por compromiso de cuentas, incluso mediante ataques de baja sofisticación.

**Figura 17. Uso de contraseñas seguras entre los participantes**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

Esta pregunta sirve como complemento a la pregunta anterior porque no basta con cambiar contraseñas, se debe tener una buena complejidad para resistir ataques de fuerza bruta. El 60,8% de los usuarios afirma usar contraseñas seguras, lo cual evidencia una contradicción, aunque todos creen tener contraseñas seguras, muy pocos las cambian, haciendo que esta práctica sea insuficiente.

**Figura 18. Verificación de enlaces y archivos antes de abrir correos**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

El 60,8% de la muestra valida la legitimidad de enlaces y archivos adjuntos; sin embargo, el 39,2% restante abre enlaces y archivos sin verificación previa. Este comportamiento facilita la ejecución de ataques basados en malware y phishing, ratificando la necesidad de robustecer las estrategias de concienciación de usuario adicionales al soporte técnico del IDS.

**Figura 19. Frecuencia de actualización del sistema operativo y software**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

Solo el 43,1% de la muestra mantiene actualizaciones constantes, mientras que el 62,8% presenta irregularidad en este proceso. Esta condición técnica preserva vulnerabilidades conocidas y explotables en los terminales, lo que representa un riesgo crítico de intrusión que invalida parcialmente la efectividad del filtrado perimetral.

**Figura 20. Conocimiento de seguridad informática institucional**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

Solo el 27,5% de los participantes valida la vigencia de políticas de seguridad, mientras que el 72,5% restante las desconoce o niega su existencia. Esta desinformación generalizada evidencia una falla crítica en la socialización de lineamientos institucionales, lo que reduce la eficacia de los controles técnicos ante posibles incidentes.

**Figura 21. Participación en capacitación en ciberseguridad**
Fuente: Elaboración propia a partir de encuesta aplicada en 2025.

El 29,4% de la muestra ha recibido formación técnica en ciberseguridad, frente a un 70,6% que carece de instrucción formal. Este déficit educativo se correlaciona directamente con la recurrencia de errores operativos identificados en las fases previas del diagnóstico institucional.

#### 5.2.4 Análisis de la encuesta pregunta abierta

Con el fin de conocer la percepción de los usuarios sobre la seguridad informática en el Instituto Universitario de la Paz, se incluyó la siguiente pregunta abierta: *¿Qué medidas cree que deberían fortalecerse en UNIPAZ para mejorar la seguridad informática?*

**Tabla 2. Análisis cualitativo de la pregunta abierta**

| Respuesta del participante | Análisis interpretativo |
|---|---|
| "Como evitar ciberataques y mantener la seguridad al máximo" | La respuesta revela preocupación general por la seguridad, pero muestra desconocimiento sobre medidas específicas. Refuerza la necesidad de formación básica y de un sistema capaz de proteger incluso a usuarios sin conocimientos técnicos. |
| "Conferencias interactivas" | Sugiere que la sensibilización debe ir más allá de documentos y circulares y buscar formatos que realmente conecten con los usuarios. |
| "Tener un protocolo de respuesta ante ciberataques, capacitar al personal y capacitar a los estudiantes." | El encuestado entiende que la seguridad no solo consiste en prevenir, sino saber reaccionar. Indica la falta de protocolos formales en UNIPAZ y la necesidad de formación para todos los perfiles. |
| "Mejorar la seguridad en redes" | Aunque breve, confirma que desde la percepción estudiantil existe conciencia de que la infraestructura de red no es suficientemente robusta. Da respaldo al proyecto como una respuesta a esa debilidad. |
| "Un programa o una campaña sobre cómo prevenir este tipo de incidentes" | El encuestado pide prevención, no solo reacción. Esto evidencia que, aunque no conozca soluciones técnicas, sí existe disposición a aprender, lo cual favorece la implementación de herramientas como el IDS si se acompañan de divulgación. |
| "Capacitaciones" | Demuestra que los encuestados entienden que la seguridad no depende solo de tecnología, sino de hábitos. |
| "Explicar cómo funciona el internet con charlas con los estudiantes ya que algunas personas tienen poco conocimiento sobre la ciberseguridad" | Refleja un nivel muy básico de alfabetización digital entre parte de la comunidad. |
| "Dar capacitaciones o guías básicas de seguridad para diversas personas de edad mayor, ya que son los más frecuentes a caer en estos links maliciosos." | Esta respuesta introduce un grupo vulnerable específico dentro de la institución. Reafirma que el modelo de seguridad debe considerar diferentes perfiles de usuario y redirige la solución hacia la educación y la prevención social. |
| "Hacer una capacitación para poder detectar el Phishing" | Esta respuesta confirma que el phishing es la amenaza más visible entre los usuarios. |
| "Lo más importante diría yo es algún método de doble verificación" | La propuesta de autenticación multifactor indica la idea de que el sistema de seguridad debe ser integral y combinar herramientas automáticas con políticas de acceso seguro. |
| "Realizar charlas de orientación respecto al tema de seguridad informática" | Coincide con la mayoría de las respuestas: la necesidad principal que los estudiantes sienten es formativa, lo cual deja claro que los procesos institucionales actuales son insuficientes o inexistentes. |
| "Crear un laboratorio real para poder enseñar de mejor manera estos ataques y así promover la enseñanza a nivel general" | Sugiere que la ciberseguridad debería enseñarse de manera aplicada y no solo teórica. El IDS del proyecto podría integrarse como herramienta educativa. |
| "Sería importante implementar programas de capacitación y concientización para todo el personal y los estudiantes sobre el uso responsable de los sistemas informáticos y la detección de amenazas como el phishing o el malware." | Refuerza la necesidad de formación institucional, no solo individual. Habla de estudiantes y administrativos, mostrando que la seguridad debe ser transversal. |
| "Menos teoría, más prácticas" | Confirma que el modelo de formación actual no está funcionando. Sugiere un enfoque pedagógico basado en experiencia real, lo cual encaja con el desarrollo del prototipo de IDS como herramienta demostrativa. |
| "En UNIPAZ deberían fortalecerse las medidas de seguridad informática mediante la actualización constante de los sistemas, el uso obligatorio de contraseñas seguras, la capacitación del personal y estudiantes en ciberseguridad, y la implementación de copias de respaldo y monitoreo permanente de la red." | Confirma que hay usuarios con criterio técnico claro y que la solución propuesta responde exactamente a necesidades reales. |
| "En UNIPAZ deberían fortalecerse medidas como la capacitación constante a estudiantes y personal sobre ciberseguridad, el uso obligatorio de contraseñas seguras y autenticación de dos factores, además de mejorar los sistemas de respaldo de información y la detección de accesos no autorizados. También sería importante actualizar los equipos y software con regularidad para evitar vulnerabilidades." | El encuestado menciona monitoreo, actualizaciones, contraseñas seguras, MFA y detección de intrusiones. |

Fuente: Elaboración propia.

El diagnóstico aplicado a 51 integrantes de la comunidad académica evidencia una disociación entre el conocimiento básico y la ejecución de prácticas preventivas, lo que incrementa la superficie de riesgo en UNIPAZ. Los hallazgos subrayan la necesidad de fortalecer la gobernanza de políticas, implementar programas de formación continua e integrar herramientas de monitoreo automatizado.

### 5.3 DISEÑO DE LA ARQUITECTURA DEL IDS

El sistema fue diseñado bajo una arquitectura modular compuesta por:

1. **Módulo de captura:** Obtención de paquetes mediante Scapy.
2. **Módulo de procesamiento:** Extracción de características del tráfico.
3. **Módulo de almacenamiento:** Registro en base de datos SQLite3.
4. **Módulo de análisis:** Clasificación mediante modelo de Machine Learning.
5. **Módulo de alertas:** Notificaciones vía interfaz gráfica y Telegram.

Esta arquitectura permite el monitoreo continuo del tráfico y la detección de anomalías en tiempo real.

*Figura 22. Arquitectura y flujo operativo del IDS — Fuente: Elaboración propia.*

#### 5.3.1 Lógica de detección y flujo de datos

El sistema integra dos enfoques complementarios para la identificación de intrusiones. El primero emplea reglas heurísticas para la detección inmediata de amenazas conocidas, como intentos de acceso a puertos inusuales o saturación de tráfico. El segundo utiliza un modelo de redes neuronales de tipo Perceptrón Multicapa (MLP) con capas ocultas, diseñado para reconocer patrones no lineales y ataques de día cero.

Para la gestión de eventos, la función `guardar_ataque` actúa como núcleo operativo, coordinando el registro en la base de datos y activando un mecanismo de control de frecuencia para mitigar la fatiga de alertas por una misma dirección IP.

*Figura 23. Función central de manejo de eventos de ataque — Fuente: Elaboración propia.*
*Figura 24. Control de frecuencia de alertas en el sistema IDS — Fuente: Elaboración propia.*

El flujo operativo se inicia con el filtrado perimetral (firewall) y continúa con el análisis del IDS, el cual clasifica el tráfico como normal o anómalo según el modelo predictivo entrenado.

*Figura 25. Diagrama de flujo de un sistema IDS — Fuente: Elaboración propia.*

#### 5.3.2 Componentes Tecnológicos e Instrumentos de Validación

La implementación técnica se apoya en un ecosistema de herramientas especializadas, seleccionadas por su capacidad de integración y rendimiento:

- **Desarrollo:** Python como núcleo del sistema, utilizando Joblib para la optimización de carga de modelos y Matplotlib para la generación de métricas visuales.
- **Gestión de Red:** Scapy para la manipulación de paquetes y Wireshark para la validación de protocolos en la infraestructura de UNIPAZ.
- **Análisis de Datos:** Modelado predictivo desarrollado en Scikit-learn, con estructuras de datos gestionadas mediante Pandas y NumPy.
- **Base de Datos:** SQLite3 para el almacenamiento local y seguro de intrusiones detectadas.

*Figura 26. Funcionamiento general de Scapy — Fuente: Adaptado de Scapy Documentation.*
*Figura 27. Vista de la base de datos ataques_detectados.db — Fuente: Elaboración propia.*
*Figura 28. Captura de tráfico de red en Wireshark para la red UNIPAZ — Fuente: Elaboración propia mediante captura en Wireshark.*

Para la validación del sistema, se emplearon Metasploit, Nmap y Hping3 para simular escenarios de ataque reales, tales como Port Scan, SYN Flood, DoS y DDoS, garantizando la calibración de la sensibilidad del modelo de detección.

*Figura 29. Ejecución de ataque de tipo SYN Flood con Metasploit — Fuente: Elaboración propia mediante Metasploit Framework.*

#### 5.3.3 Interfaz Gráfica y Gestión de Usuario

La interfaz desarrollada en PyQt5 permite la interacción directa con el motor de detección. El diseño evolucionó desde prototipos funcionales hasta una versión final que integra monitoreo en vivo y exportación de reportes en formato CSV.

*Figura 30. Primer diseño de la interfaz IDS — Fuente: Elaboración propia.*
*Figura 31. Ultimo diseño de la interfaz IDS — Fuente: Elaboración propia.*

El flujo de interacción entre el administrador y el sistema se define mediante las capacidades de inicio de monitoreo, visualización estadística y recepción de alertas remotas.

*Figura 32. Diagrama caso de uso interfaz de usuario IDS — Fuente: Elaboración propia.*

### 5.4 IMPLEMENTACIÓN DEL SISTEMA

La implementación se desarrolló en Python, integrando librerías especializadas para análisis de paquetes, procesamiento de datos y entrenamiento del modelo.

Se configuró un entorno de pruebas controlado donde se ejecutaron simulaciones de ataques utilizando Metasploit y herramientas de generación de tráfico malicioso.

Adicionalmente, se desarrolló una interfaz gráfica en PyQt5 que permite visualizar eventos detectados, métricas y registros históricos.

### 5.5 CONSTRUCCIÓN DEL DATASET

Se generó un conjunto de datos propio a partir de la captura de tráfico normal y malicioso en laboratorio.

El dataset incluyó variables como:

- Dirección IP origen/destino
- Puerto
- Protocolo
- Tamaño de paquete
- Frecuencia de conexión

*Figura 33. Dataset generado a partir de simulaciones — Fuente: Elaboración propia.*

Los datos fueron etiquetados para su uso en el entrenamiento supervisado del modelo.

### 5.6 ENTRENAMIENTO DEL MODELO DE MACHINE LEARNING

El modelo fue entrenado utilizando datos previamente etiquetados, permitiendo clasificar eventos como tráfico legítimo o intrusión.

Se aplicaron procesos de:

- Limpieza de datos
- Normalización
- División entrenamiento/prueba
- Ajuste de parámetros

*Figura 34. Matriz de Confusión IDS — Fuente: Elaboración propia.*

**Tabla 3. Matriz de confusión para clasificación de tráfico**

|  | Tráfico Normal | Ataque Detectado | Total, Real |
|---|---|---|---|
| **Tráfico Normal (Negativo)** | 94 (Verdaderos Negativos) | 1 (Falso Positivo) | 95 |
| **Ataque (Positivo)** | 0 (Falso Negativo) | 105 (Verdaderos Positivos) | 105 |
| **Total, Predicción** | 94 | 106 | 200 |

Fuente: Elaboración propia.

La evaluación del rendimiento sobre una muestra de 200 registros permitió identificar la eficacia del sistema en la distinción de eventos:

- **Verdaderos Negativos (TN):** 94 casos de tráfico normal identificados correctamente.
- **Verdaderos Positivos (TP):** 105 ataques detectados con éxito.
- **Falsos Positivos (FP):** 1 registro de tráfico legítimo clasificado erróneamente como ataque.
- **Falsos Negativos (FN):** 0 omisiones; el sistema detectó la totalidad de las amenazas presentes.

### 5.7 PRUEBAS DE ATAQUE CONTROLADAS

Con el uso de las herramientas Metasploit, hping3 y Nmap se ejecutaron simulaciones de:

- SYN Flood.
- DoS.
- DDoS.
- Port Scan.

Estas pruebas permitieron evaluar la capacidad de detección del IDS frente a diferentes vectores de ataque. Previo a las simulaciones, se estableció una línea base del tráfico real en la institución mediante capturas en la red de administrativos (158.1 pps promedio) y la red de estudiantes (59.6 pps promedio).

*Figura 35. Captura de red con Wireshark en la red Administrativos — Fuente: Elaboración propia mediante captura en Wireshark.*
*Figura 36. Captura de red con Wireshark en la red Estudiantes — Fuente: Elaboración propia mediante captura en Wireshark.*

La validación del entorno se realizó extrayendo métricas de duración, volumen de bytes y conteo de paquetes para asegurar que el sistema soporte la carga operativa de UNIPAZ.

*Figura 37. Panel de Wireshark Statistic en la red Administrativos — Fuente: Elaboración propia mediante captura en Wireshark.*
*Figura 38. Panel de Wireshark Statistic en la red Estudiante — Fuente: Elaboración propia mediante captura en Wireshark.*

**Tabla 4. Comparación entre tráfico de red y capacidad del IDS**

| Escenario / Red | Duración (s) | Paquetes Capturados | Bytes Capturados | Paquetes/ Segundo (pps) | Bytes/ Segundo (B/s) | Tamaño Promedio Paquete (bytes) |
|---|---|---|---|---|---|---|
| Red Administrativos | 2289.053 | 362,004 | 54,322,025 | 158.1 | 23,000 | 150 |
| Red Estudiantes | 622.403 | 37,088 | 15,142,289 | 59.6 | 24,000 | 408 |
| Capacidad Máxima del IDS — Solo captura con Scapy | 3600 | 54,000,000 | 7.5 GB | 5,000 a 15,000 | 300,000 | 145 |
| Captura + inspección básica | 3600 | 14,400,000 | 21 GB | 1,000 a 4,000 | 600,000 | 150 |
| Captura + ML + SQLite + Telegram | 3600 | 3,600,000 | 540 MB | 300 a 1,000 | 150,000 | 150 |

Fuente: Elaboración propia.

### 5.8 EVALUACIÓN DEL DESEMPEÑO

El rendimiento del sistema se evaluó mediante métricas de clasificación:

- Precisión
- Tasa de detección
- Falsos positivos
- Falsos negativos

Los resultados evidenciaron una alta capacidad de identificación de tráfico malicioso y una reducción significativa de alertas erróneas. Las pruebas ejecutadas con hping3, Metasploit y Nmap confirmaron la efectividad del modelo.

**Tabla 5. Resultados de pruebas de ataque SYN Flood**

| Herramienta | Protocolo | Cantidad de intentos | Éxito de detección | Ataques simultáneos |
|---|---|---|---|---|
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | DoS |
| Metasploit | TCP | 1 | 100 % | DDoS |
| hping3 | TCP | 1 | 100 % | No aplica |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100 % | Port Scan, DoS |
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | DDoS |
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | No aplica |
| Metasploit | TCP | 1 | 100 % | DoS |
| hping3 | TCP | 1 | 100 % | No aplica |
| Metasploit | TCP | 1 | 100 % | DDoS, Port Scan |
| hping3 | TCP | 1 | 100 % | DDoS |
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | DoS |
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | Port Scan |
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | DDoS |

Fuente: Elaboración propia.

**Tabla 6. Resultados de pruebas de ataque DoS**

| Herramienta | Protocolo | Cantidad de intentos | Éxito de detección | Ataques simultáneos |
|---|---|---|---|---|
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | SYN Flood |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | DDoS |
| Metasploit | TCP | 1 | 100% | DDoS |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | SYN Flood, DDoS |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | DDoS |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | DDoS |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | SYN Flood |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | DDoS |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | Port Scan |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | SYN Flood |

Fuente: Elaboración propia.

**Tabla 7. Resultados de pruebas de ataque DDoS**

| Herramienta | Protocolo | Cantidad de intentos | Éxito de detección | Ataques simultáneos |
|---|---|---|---|---|
| Metasploit | TCP | 1 | 100 % | No aplica |
| hping3 | TCP | 1 | 100 % | SYN Flood |
| Metasploit | TCP | 1 | 100% | DoS |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | Port Scan |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | SYN Flood, DoS |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | DoS |
| hping3 | TCP | 1 | 100% | No aplica |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | Port Scan |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | SYN Flood |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | DoS |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | DoS |
| Metasploit | TCP | 1 | 100% | No aplica |
| hping3 | TCP | 1 | 100% | SYN Flood |

Fuente: Elaboración propia.

**Tabla 8. Resultados de pruebas de ataque Port Scan**

| Herramienta | Cantidad de intentos | Éxito de detección | Ataques simultáneos |
|---|---|---|---|
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | SYN Flood |
| Nmap | 1 | 100 % | DoS |
| Nmap | 1 | 100 % | DDoS |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | SYN Flood, DoS |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | DoS |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | DDoS |
| Nmap | 1 | 100 % | SYN Flood |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | DoS |
| Nmap | 1 | 100 % | DDoS |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | SYN Flood, DoS |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | DDoS |
| Nmap | 1 | 100 % | No aplica |
| Nmap | 1 | 100 % | SYN Flood |

Fuente: Elaboración propia.

Tras 20 escenarios de prueba por categoría, el sistema alcanzó una precisión del 100%, con una tasa de falsos negativos (FN) y falsos positivos (FP) del 0%. El tiempo de respuesta se mantuvo inferior a un segundo, garantizando la detección en tiempo real y la comunicación inmediata de incidentes.

*Figura 39. Captura 2 de Notificación Telegram - Ataque en Curso — Fuente: Elaboración propia.*

---

## 6. CONCLUSIONES

Se implementó un sistema de detección de intrusiones basado en técnicas de Machine Learning, capaz de monitorear y analizar el tráfico de la red institucional, permitiendo la identificación de comportamientos anómalos asociados a amenazas cibernéticas. El diagnóstico inicial evidenció vulnerabilidades en la infraestructura de red, especialmente relacionadas con intentos de acceso no autorizado, escaneo de puertos y tráfico automatizado malicioso, lo que confirmó la necesidad de mecanismos avanzados de detección y permitió evidenciar la exposición de la red institucional frente a estas amenazas. Asimismo, el diseño del sistema IDS bajo una arquitectura modular facilitó la integración de procesos de captura, procesamiento, análisis y almacenamiento de datos, garantizando un flujo continuo de monitoreo y clasificación de eventos de red, así como el monitoreo continuo del tráfico de red.

Las pruebas de simulación de ataques, incluyendo SYN Flood, DoS, DDoS y Port Scan, permitieron validar el funcionamiento del sistema en entornos controlados, evidenciando su capacidad para detectar intrusiones en tiempo real. De igual manera, la implementación del sistema en un entorno de prueba, gestionada mediante metodología Kanban, permitió validar su funcionamiento operativo y su capacidad de análisis en tiempo real. El modelo de Machine Learning entrenado con el dataset generado logró niveles satisfactorios de precisión y tasa de detección, reduciendo la ocurrencia de falsos positivos y falsos negativos durante las pruebas experimentales; en este mismo sentido, la evaluación del desempeño evidenció resultados favorables frente a ataques simulados. Adicionalmente, la integración de mecanismos de alerta mediante interfaz gráfica y notificaciones automatizadas fortaleció la capacidad de respuesta ante incidentes de seguridad.

Desde el ámbito institucional, el sistema desarrollado constituye una herramienta de apoyo para el fortalecimiento de la ciberseguridad, permitiendo mejorar los procesos de monitoreo y gestión de eventos. Finalmente, el proyecto demuestra la viabilidad de aplicar técnicas de inteligencia artificial en la protección de infraestructuras educativas, sirviendo como base para futuras implementaciones y líneas de investigación en seguridad informática.

---

## 7. RECOMENDACIONES

Se recomienda a la institución fortalecer la infraestructura de ciberseguridad mediante la integración del sistema de detección de intrusiones desarrollado con otras herramientas de defensa perimetral, como firewalls de nueva generación y sistemas de prevención de intrusiones (IPS), con el fin de establecer un esquema de protección multicapa.

Asimismo, se sugiere ampliar el alcance del sistema mediante su implementación en entornos de producción institucional, permitiendo el monitoreo permanente del tráfico de red y la generación de alertas tempranas ante incidentes de seguridad reales.

Desde el componente técnico, es recomendable entrenar el modelo de Machine Learning con datasets de mayor volumen y diversidad, incluyendo tráfico de diferentes periodos académicos, lo que permitiría mejorar la capacidad de generalización del sistema y reducir aún más los falsos positivos.

Se propone igualmente incorporar nuevos algoritmos de clasificación y técnicas de aprendizaje profundo que permitan comparar el desempeño del sistema frente a modelos más robustos.

En el ámbito institucional, se recomienda complementar la implementación tecnológica con programas de capacitación en ciberseguridad dirigidos a estudiantes, docentes y personal administrativo, con el propósito de reducir vulnerabilidades asociadas al factor humano.

Finalmente, se sugiere utilizar el prototipo desarrollado como base para futuros proyectos de investigación en seguridad informática, así como para el fortalecimiento de laboratorios académicos orientados a la simulación y análisis de ciberataques.

---

## BIBLIOGRAFÍA

- ANDERSON, James P. *Computer Security Threat Monitoring and Surveillance* [en línea]. Washington D.C.: James P. Anderson Co., 1980. Disponible en: https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/ande80.pdf Consultado: 20 marzo 2026.

- ASAMBLEA NACIONAL CONSTITUYENTE. *Constitución Política de Colombia. Artículo 15 — Hábeas Data*. Bogotá D.C.: Asamblea Nacional Constituyente, 1991. Disponible en: https://www.constitucioncolombia.com/titulo-2/capitulo-1/articulo-15 Consultado: 20 marzo 2026.

- CONGRESO DE LA REPÚBLICA DE COLOMBIA. *Ley 1581 de 2012: Por la cual se dictan disposiciones generales para la protección de datos personales*. Bogotá D.C.: Diario Oficial No. 48.587, 2012. Disponible en: https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=49981 Consultado: 20 marzo 2026.

- DEPARTAMENTO NACIONAL DE PLANEACIÓN. *Documento CONPES 3701: Política de Seguridad Digital*. Bogotá D.C.: DNP, 2011. Disponible en: https://colaboracion.dnp.gov.co/CDT/Conpes/Económicos/3701.pdf Consultado: 20 marzo 2026.

- DENNING, Dorothy E. *An Intrusion-Detection Model* [en línea]. 1986. Disponible en: https://www.academia.edu/8674514/An_Intrusion_Detection_Model Consultado: 20 marzo 2026.

- DENNING, Dorothy E. An intrusion-detection model. En: *IEEE Transactions on Software Engineering*. Febrero, 1987. vol. 13, no. 2, p. 222–232.

- FORTINET. *¿Qué es un sistema de detección de intrusos (IDS)?* [en línea]. Disponible en: https://www.fortinet.com/lat/resources/cyberglossary/intrusion-detection-system Consultado: 20 marzo 2026.

- GONZÁLEZ, David. *IDS V1.01: Estudio sobre sistemas de detección de intrusos* [en línea]. Disponible en: https://dgonzalez.net/papers/ids/ids_v1.0.pdf Consultado: 20 marzo 2026.

- HAROON, Shahzad; HUSSAIN, Syed Sajjad. Evaluación integral del rendimiento de un sistema de detección de intrusiones en la red mediante un enfoque de aprendizaje automático. En: *Journal of Information Security and Risk Communication*. 2023. vol. 17, no. 1. Disponible en: https://doi.org/10.31645/jisrc-019-01 Consultado: 20 marzo 2026.

- IBRAHIM, Laheeb M.; TAHA, Dujan B.; MAHMOD, Mahmod S. A comparison study for intrusion database (KDD99, NSL-KDD) based on self organization map (SOM) artificial neural network. En: *Journal of Engineering Science and Technology*. 2013. vol. 8, no. 1, p. 107–119.

- IBM. *Seguridad informática* [en línea]. Disponible en: https://www.ibm.com/es-es/topics/it-security Consultado: 20 marzo 2026.

- INTERNATIONAL ORGANIZATION FOR STANDARDIZATION. *ISO/IEC 27001:2013 Information technology — Security techniques — Information security management systems — Requirements*. Ginebra: ISO, 2013. Disponible en: https://www.iso.org/standard/54534.html Consultado: 20 marzo 2026.

- LINKTIC. *Panorama completo de la ciberseguridad en Colombia* [en línea]. Bogotá: LinkTIC, 2025. Disponible en: https://linktic.com/blog/panorama-completo-de-la-ciberseguridad-en-colombia/ Consultado: 20 marzo 2026.

- MIJALKOVIC, Jovana; SPOGNARDI, Angelo. Reducción de la tasa de falsos negativos en sistemas de detección de intrusiones en redes basados en aprendizaje profundo. En: *Algorithms*. 2022. vol. 15, no. 8, p. 258. Disponible en: https://doi.org/10.3390/a15080258 Consultado: 20 marzo 2026.

- MINISTERIO DE COMERCIO, INDUSTRIA Y TURISMO. *Decreto 1377 de 2013: Por el cual se reglamenta parcialmente la Ley 1581 de 2012*. Bogotá D.C.: Diario Oficial No. 48.834, 2013. Disponible en: https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=53646 Consultado: 20 marzo 2026.

- RAMAIAH, Mangayarkarasi; VANMATHI, C.; KHAN, Mohammad Zubair; VANITHA; DEEPA, M. Un sistema eficiente de detección de intrusiones para combatir las ciberamenazas mediante un modelo de red neuronal profunda. En: *ITB Journal of ICT Research and Applications*. 2023. vol. 17, no. 3. Disponible en: https://doi.org/10.5614/itbj.ict.res.appl.2023.17.3.2 Consultado: 20 marzo 2026.
