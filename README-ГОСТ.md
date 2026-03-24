# ИНСТРУКЦИЯ CLI ДЛЯ ПОДПИСИ

## Установка КриптоПро CSP

Скачать и установить подходящий дистрибутив CSP 5.0 R4 или CSP 5.0 R3: https://cryptopro.ru/products/csp/downloads
В состав CSP входит пробная лицензия.

Для проверки ГОСТ подписи необходимо отключить усиленный контроль ключей `StrengthenedKeyUsageControl`, если он включен.
Найти параметр `StrengthenedKeyUsageControl`, проверить его и задать ему значение `0` (отключить) можно в:
* Windows: `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Crypto Pro\Cryptography\CurrentVersion\Parameters`
* *nix: разделе `[Parameters]` конфига `/etc/opt/cprocsp/config64.ini`
* Android: разделе `[Parameters]` конфига `config.ini` в ресурсах `res/raw` архива `SharedLibrary.aar`

## Подготовка Java CSP

Скачать дистрибутив Java CSP 5.0-A R4 или R3 для Java 11+: https://cryptopro.ru/sites/default/files/private/csp/50/13700/java-csp-5.0.49196-A-d260d15b.zip или https://cryptopro.ru/sites/default/files/private/csp/50/13003/java-csp-5.0.45559-A-b34f3a2f.zip
Распаковать в папку, например, /path/to/java-csp, в дальнейшем потребуется путь к папке с jar-файлами.
В состав Java CSP входит пробная лицензия.

Java CSP содержит несколько криптопровайдеров для работы с КриптоПро CSP:
* `ГОСТ` - криптопровайдер `JCSP`, класс `ru.CryptoPro.JCSP.JCSP`
* `RSA` - криптопровайдер `JCSPRSA`, класс `ru.CryptoPro.JCSP.JCSPRSA`
* `ECDSA` - криптопровайдер `JCSPECDSA`, класс `ru.CryptoPro.JCSP.JCSPECDSA`

## Добавление apksig.jar

apksig.jar можно положить в папку с распакованным Java CSP, например, в папку `/path/to/java-csp`.

Исходный [apksig](https://android.googlesource.com/platform/tools/apksig/) не поддерживает ГОСТ алгоритм, добавление другого ID-value pair, добавление отдельной подписи и повторную подпись v4.

## Создание тестового ключевого контейнера для подписи на алгоритме ГОСТ 34.10-2012 (256)

Создать ключевой контейнер можно в тестовом УЦ: https://testgost2012.cryptopro.ru/certsrv/
Алгоритм ключа должен быть ГОСТ 2012 (256), сертификат - для подписи кода.
Ключевой контейнер будет создан в папке пользователя ("C:\Users\<username>\Local\AppData\Crypto Pro" или /var/opt/cprocsp/keys/<username>).
Выполнение команд должно осуществляться под управлением учетной записи этого пользователя, чтобы был доступ к этому ключу.

Далее тестовый ключевой контейнер с типом `HDIMAGE`, именем `gost_test` и паролем `12345678`.

## О ГОСТ подписи, добавляемой apksig.jar

ID для ID-value pair с подписью на ГОСТ алгоритме: `0x2f02bfc7`
Поддерживается алгоритм подписи `ГОСТ 34.11-2012 (256) / 34.10-2012 (256)`.
Схема ГОСТ подписи соответствует `APK Signature Scheme V2`.

## Примеры команд для добавления ГОСТ подписи

Далее тестовое приложение - app.apk. 
Для подписи и проверки ГОСТ подписи передается classpath с указанием пути к Java CSP и apksig.jar `-cp /path/to/java-csp/*`.

Пример добавления подписи app.apk ключом на ГОСТ алгоритме:
```
java -Dkeytool.compat=true -Duse.cert.stub=true -cp /path/to/java-csp/* com.android.apksigner.ApkSignerTool sign \
--append-signature \
--v4-signing-enabled false --v3-signing-enabled false --v2-signing-enabled false --gost-signing-enabled true --v1-signing-enabled false --stamp-timestamp-enabled false \
--ks NONE --ks-type HDIMAGE --ks-key-alias gost_test --ks-pass pass:12345678 -key-pass pass:12345678 --ks-provider-name JCSP --ks-provider-class ru.CryptoPro.JCSP.JCSP --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 \
app.apk
```

ГОСТ подпись выполняется с параметром `--append-signature` и новым параметром `--gost-signing-enabled true`, при этом другие *-signing-enabled должны быть явно отключены.
`--gost-signing-enabled true` означает подпись на ГОСТ алгоритме.
Для создания ГОСТ подписи выполняется регистрация криптопровайдера Java CSP с помощью параметров *-provider-*
В штатном apksigner не поддерживается `--gost-signing-enabled true`.
После подписи в Signing Block app.apk вместо padding вставляется ID-value pair с подписью на ГОСТ алгоритме.

Пример проверки подписи app.apk:
```
java -Dkeytool.compat=true -Duse.cert.stub=true -cp /path/to/java-csp/* com.android.apksigner.ApkSignerTool verify \
--verbose --print-certs --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 \
app.apk
```

Для проверки ГОСТ подписи выполняется регистрация криптопровайдера Java CSP с помощью параметров *-provider-*
В штатном apksigner не поддерживается `--provider-class --provider-pos`.

Если требуется проверить подпись формата v4, то в команду проверки добавляется `--v4-signature-file app.apk.idsig` с указанием v4-файла, например,
```
java -Dkeytool.compat=true -Duse.cert.stub=true -cp /path/to/java-csp/* com.android.apksigner.ApkSignerTool verify \
--verbose --print-certs --provider-class ru.CryptoPro.JCSP.JCSP --provider-pos 1 \
--v4-signature-file app.apk.idsig \
app.apk
```
Для проверки подписи должен быть отключен усиленный контроль ключа.

Проверка штатным apksigner может быть выполнена так:
```
apksigner verify --verbose --print-certs app.apk
```

## Подпись V4 после добавления ГОСТ подписи

Если app.apk имеет v4-подпись, то после добавления нового ID-value pair она станет невалидной. 
Для повторного создания v4-подписи придется прибегнуть к команде вида:
```
java -Dkeytool.compat=true -Duse.cert.stub=true com.android.apksigner.ApkSignerTool sign \
--append-signature --v4-single-signing-enabled true --v4-signing-enabled true --v3-signing-enabled false --v2-signing-enabled false --v1-signing-enabled false --stamp-timestamp-enabled false \
--ks NONE --ks-type HDIMAGE --ks-key-alias rsa_test --ks-pass pass:12345678 -key-pass pass:12345678 --ks-provider-name JCSPRSA --ks-provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-class ru.CryptoPro.JCSP.JCSPRSA --provider-pos 1 \
app.apk
```

В команду проверки добавляются параметры `--append-signature --v4-signing-enabled true` и новый параметр `--v4-single-signing-enabled true`, при этом другие *-signing-enabled должны быть явно отключены.
`--v4-single-signing-enabled true` означает повторную v4-подпись.
В штатном apksigner не поддерживается создание одной только v4-подписи.

В этом примере предполагается, что ключ на алгоритме `RSA` для создания подписи v1, v2, v3 или v4 хранится в формате, аналогичном `gost_test`, поэтому указаны соответствующие хранилище, криптопровайдеры и т.п.
В ином случае, например, если ключ - `pfx`, `jks` и т.п., следует использовать стандартные команды, предлагаемые `apksig`.
В случае успеха будет создан файл `app.apk.idsig`.

# ИНСТРУКЦИЯ ДЛЯ ANDROID ДЛЯ ПРОВЕРКИ ПОДПИСИ

## Android CSP SDK

`Android CSP SDK` - это "толстый" SDK, куда входят:
* библиотеки криптопровайдера КриптоПро CSP
* файлы конфигурации и лицензии
* файлы хэшей для контроля целостности
* библиотеки и ресурсы java-криптопровайдеров (Java CSP и другие)

Встраивание выполняется путем добавления SDK в состав приложения.

Здесь https://docs.cryptopro.ru/android/samples/ACSPExamples/ACSPExamples имеется пример встраивания `Android CSP SDK`.

'Android CSP SDK' включает несколько aar-библиотек, они находятся в папке examples\ACSPExamples\libs: csp-base.aar, csp-gui.aar, JInitCSP.aar, SharedLibrary.aar.
Их нужно добавить в свой проект, например, положив в папку libs в корне проекта (где build.gradle) и добавив в build.gradle строку:
```
implementation fileTree(dir: 'libs', include: ['*.aar'])
```

Встраивание имеет свои особенности, например, контроль целостности. 
На этапе отладке он упрощенный, охватывает только so-файлы библиотек, а в релизе требуются дополнительные хэши dex-файлов, которые (хэши) надо рассчитывать.
В debug приложении (debuggable=true) dex-контроль не осуществляется.

## Инициализация КриптоПро CSP

Иницициализация КриптоПро CSP выполняется с помощью вызова (см. `examples/ACSPExamples/src/main/java/ru/cryptopro/acsp/examples/crypto/init/Init.kt`)
```
int errorCode = CSPConfig.init(context);
```
В случае ошибки errorCode вернет код, отличный от 0.

Возможные коды ошибок:
* `CSPConfig.CSP_INIT_UNKNOWN` - состояние инициализации неопределенно;
* `CSPConfig.CSP_INIT_CONTEXT` - ошибка при передаче пустого (null) контекста приложения;
* `CSPConfig.CSP_INIT_CREATE_INFRASTRUCTURE` - ошибка при подготовке окружения криптопровайдера;
* `CSPConfig.CSP_INIT_COPY_RESOURCES` - ошибка при копировании ресурсов криптопровайдера при подготовке окружения;
* `CSPConfig.CSP_INIT_CHANGE_WORK_DIR` - ошибка при переходе в папку приложения;
* `CSPConfig.CSP_INIT_INVALID_LICENSE` - ошибка при проверке лицензии криптопровайдера;
* `CSPConfig.CSP_STORE_LIBRARY_PATH` - ошибка при создании дефолтного java-хранилища корневых сертификатов;
* `CSPConfig.CSP_INIT_INVALID_INTEGRITY` - ошибка при инициализации контроля целостности;
* `CSPConfig.CSP_INIT_UNSUPPORTED` - ошибка "не поддерживаемая ОС";
* `CSPConfig.CSP_INIT_APP_CONTEXT` - ошибка получения контекста приложения;
* `CSPConfig.CSP_INIT_CSP_NOT_FOUND` - ошибка из-за отсутствия библиотек криптопровайдера;
* `CSPConfig.CSP_INIT_INVALID_INTEGRITY_CHECK` - ошибка при выполнении контроля целостности;
* `CSPConfig.CSP_INIT_LICENSE` - ошибка при чтении лицензии криптопровайдера;
* `CSPConfig.CSP_INIT_OK` - инициализация выполнена успешно.

Важно, чтобы действия, которые могут повлечь появление окон CSP (БиоДСЧ, ввод пароля, выбор считывателя т др.), выполнялись в отдельном потоке.

## Регистрация Java CSP

В случае успешной иницициализации КриптоПро CSP далее нужно выполнить регистрацию java-криптопровайдера Java CSP для проверки ГОСТ подписи:
```
Security.addProvider(JCSP());
```
Для apksig этого пока должно быть достаточно.

## Использование apksig.jar

К проекту следует подключить библиотеку apksig.jar, например, положив в папку libs в корне проекта (где build.gradle) и добавив в build.gradle строку:
```
implementation fileTree(dir: 'libs', include: ['*.jar'])
```

Проверку подписи app.apk в виде файла можно выполнить программно, например:
```
import java.io.File;
import java.nio.channels.FileChannel;
import com.android.apksig.ApkVerifier;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;

{
    File apkFile = ... // проверяемый app.apk
    DataSource ds = DataSources.asDataSource(FileChannel.open(apkFile.toPath()));
    ApkVerifier.Builder builder = new ApkVerifier.Builder(ds);
    ApkVerifier.Result result = builder.build().verify(); // полная проверка
}
```
Можно проверить в `result`:
* общий статус `result.isVerified()` - функция должна вернуть true
* статус `result.isVerifiedUsingGostScheme()` - функция должна вернуть true
* наличие `result.getGostSchemeSigners()` - функция должна вернуть непустой список подписантов
* наличие ошибок в `result.getGostSchemeSigners().get(i).getErrors()` - функция должна вернуть непустой список ошибок подписанта
* сертификат ключа подписи в `result.getGostSchemeSigners().get(i).getCertificate()`
* иное

## Проверка цепочки сертификата ключа подписи
TODO