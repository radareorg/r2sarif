# PLAN

* Load a Sarif Driver
  * name, product and semantic version
  * contain all rule ids
    * ids are unique per each driver

* Load Sarif Document
  * Have multiple runs (array of tool+results)
    * each tool have a driver associated
    * the array of results must contain the list of findings

* Saving Sarif Documents
  * Store each finding on the associated driver block

# r2sarif

  The plugin must allow to do the following actions

* drivers
  * import
    * from sarif document
    * from sarif driver document
  * list
  * select
  * export
* finding results
  * those are associated with the drivers
  * export to file

# Sarif

## 1

- platform genera sarif
- los clientes lo pueden leer
- no se sabe que tool ha generado cada finding (la tool es platform)


## 2

- los clientes pueden subir sarif custom
- generar sarif con r2


### random

- Visualizar findings en r2
    - plugin de r2
    - plugin de iaito / web
    - documentacion
    - corriendo en localhost del cliente
- Visualizar en platform
    - webassembly
- Visualizar en workstation
- Importar ruleIds de varios sources
