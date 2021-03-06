Эта страница на [English](/README.md)

# IONDV. Registry

<h1 align="center"> <a href="https://www.iondv.com/"><img src="/registry.png" alt="IONDV. Registry" align="center"></a>
</h1>  

Registry - модуль IONDV. Framework. Является ключевым модулем, предназначенным непосредственно для работы с данными на основе структур метаданных, обеспечивает ведение и отображение данных в виде реестра.

### Кратко об IONDV. Framework

IONDV. Framework - это опенсорный фреймворк на node.js для разработки учетных приложений 
или микросервисов на основе метаданных и отдельных модулей. Он является частью 
инструментальной цифровой платформы для создания enterprise 
(ERP) приложений состоящей из опенсорсных компонентов: самого [фреймворка](https://github.com/iondv/framework), 
[модулей](https://github.com/topics/iondv-module) и готовых приложений расширяющих его 
функциональность, визуальной среды [Studio](https://github.com/iondv/studio) для 
разработки метаданных приложений.

Подробнее об [IONDV. Framework на сайте](https://iondv.com), документация доступна в [репозитории на github](https://github.com/iondv/framework/blob/master/docs/en/index.md)

## Описание и назначение модуля

Основной модуль приложения, предназначен для отображения объектов управления на странице реестра: 
навигации, форм представления, фильтров, бизнес процессов и других разделов модуля. 
Свойства и настройки объектов управления для вывода на страницу модуля задаются метаданными приложения и включают в себя:
- [x] создание классов и, входящих в них, атрибутов;
- [x] создание навигации;
- [x] создание представлений для классов;
- [x] создание бизнес-процессов;
- [x] создание шаблонов для применения расширенной функциональности посредством подключения связанных библиотек;
- [x] создание утилит для запуска каких-либо процессов или задач по расписанию;
- [x] создание текстов для уведомлений, настраиваемых в конфигурационном файле приложения. 

## Возможности модуля учета данных registry

- Отображение навигации в иерархическом виде
- Отображение списков объектов данных по условиям навигации, фильтров, результатов поиска
- Возможность создания объектов
- Отображение унифицированных форм объектов с возможностью редактирования, удаления, изменения бизнес-процессов, реализации условия отображения и перегрузки представления формы по бизнес-процессу
- Отображение различных типов атрибутов, включая связанные в виде таблиц или ссылок, геообъектов (включая поиск координат по адресу);
- Отображение данных по их семантике (условиям изменениям)
- Возможность изменения отображения и взаимодействия с атрибутами объектов через кастомизированные HTML шаблоны, получающие данные по REST-API
- Подготовка печатных форм в формате .docx и .xlsx на основе списков или данных объектов
- Отображение уведомлений пользователей
- Возможность реализации собственных кнопок действий с серверной обработкой данных

## Применение модуля на примере демо-версий проектов

Модуль _Registry_ представлен во всех демо-версиях проектов:

* **Проект [telecom-ru.iondv.com](https://telecom-ru.iondv.com/geomap), [telecom-en.iondv.com](https://telecom-en.iondv.com/geomap)** - приложение для учета телекоммуникаций в населенных пунктах. 
* **Проект [pm-gov-ru.iondv.com](https://pm-gov-ru.iondv.com/geomap)** - приложение для ведения проектной деятельности. 

На странице модуля _Registry_ представлены пункты системного меню, расположенные в верхней части страницы модуля и отображающие основные учетные объекты системы. При переходе в любой из пунктов системного меню - открывается навигация, содержащая в себе объекты системы по пунктам навигации, в совокупности представляя описание учетных объектов системы. 

В итоге, все учетные объекты системы организованны в виде списка для пунктов навигаций. Доступно редактирование или просмотр подробной информации по учетному объекту в карточке объекта, открыв ее из списка.


--------------------------------------------------------------------------  


 #### [Licence](/LICENSE) &ensp;  [Contact us](https://iondv.com) &ensp;    [English](/README.md)   &ensp; [FAQs](/faqs.md)          

--------------------------------------------------------------------------  

Copyright (c) 2018 **LLC "ION DV"**.  
All rights reserved. 