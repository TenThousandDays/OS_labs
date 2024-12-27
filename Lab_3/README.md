## Модуль ядра Linux

Требуется подготовить модуль для загрузки в ядро Linux. Модуль должен:

* сопровождаться Makefile для сборки;
* оформляться в виде файла *.ko;
* загружаться командой insmod и выгружаться командой rmmod;
* при загрузке выводить в dmesg строку «Welcome to the Tomsk State University»;
* при выгрузке выводить в dmesg строку «Tomsk State University forever!».