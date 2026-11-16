"""Interface texts (tech.md §15): the only place for user-facing strings.

Keys from §15 are the mandatory minimum; tasks add their own keys additively.
`t(key, **params)` formats a text; an unknown key is a bug and raises KeyError.
A number takes the Russian form of the word after it: `{n:нода|ноды|нод}` gives
«1 нода», «3 ноды», «5 нод» (`plural`).
"""

from __future__ import annotations

TEXT: dict[str, str] = {
    # §15 mandatory minimum
    "app.tagline": "Защита VPN-серверов на Remnawave и 3x-ui",
    "mode.check": "Проверка: настройки серверов не меняет",
    "mode.fix": "Исправление: план, разрешение, изменения",
    "mode.rollback": "Откат прошлого запуска",
    "panel.found": "Нашёл Remnawave {version} на этом сервере",
    "panel.login": "Логин администратора панели",
    "panel.password": "Пароль (не сохраняется)",
    "panel.token": "API-токен панели: Настройки → API-токены",
    "panel.ok": "Панель подключена: нод {nodes}, хостов {hosts}",
    "nodes.title": "Какие ноды защищать?",
    "access.hostkey": "Ключ сервера {node}: {fingerprint}. Это ваш сервер?",
    "access.password": "Введите пароль root для {node}. KERBEROS его не видит и не сохраняет",
    "access.admin_keys": "Чтобы вы не потеряли вход, добавим ваш ключ на ноды",
    "access.no_admin_key": (
        "Своего ключа нет. Создать ключ на сервере панели? Входить на ноды: kerberos ssh <нода>"
    ),
    "report.score": "Защищённость {score} из 100",
    "report.saved": "Отчёт сохранён: {path}",
    "plan.title": "Что исправить",
    "consent.title": "Разрешите изменения",
    "consent.accept": "Разрешаю изменения",
    "fix.self_steal.warning": (
        "KERBEROS выпустит сертификат на ваш домен, поднимет сайт и переключит Reality "
        "на этот домен. Панель перезапустит Xray на ноде: клиенты переподключатся за секунды. "
        "Будут созданы копии хостов с новым SNI, старые хосты выключатся (не удалятся). "
        "Сутки нода принимает и старое имя, чтобы клиенты успели обновить подписку."
    ),
    "fix.ssh_port.warning": (
        "SSH переедет на порт {port}. Старый порт закроется после проверки нового. "
        "Если у хостера свой фаервол, откройте в нём порт {port}, иначе KERBEROS вернёт "
        "всё через три минуты."
    ),
    "fix.key_only.warning": "Вход по паролю выключится. Входить можно будет только ключом.",
    "plan.reserve": "Резервная нода для {node}",
    "plan.reserve.none": "Без резерва",
    "plan.reserve.hint": "Если {node} заблокируют, клиенты сами перейдут на резерв",
    "fix.profile.warning": (
        "Конфиг ноды заменится проверенным конфигом KERBEROS: Reality и Hysteria2 на вашем "
        "домене. Ключи Reality и остальные ваши инбаунды сохранятся."
    ),
    "fix.mount.warning": (
        "Нода {node} перезапустится, чтобы увидеть сертификат для Hysteria2. "
        "Клиенты переподключатся за секунды."
    ),
    "apply.rolled_back": "Не применилось, откатил: {reason}",
    "apply.outside": (
        "SSH слушает новый порт {port}. Проверьте вход с вашего компьютера в новом окне "
        "терминала: {command}. KERBEROS работает на этом же сервере и фаервол хостера "
        "отсюда не видит. Без ответа за три минуты всё вернётся само."
    ),
    "apply.outside.keys": "Enter: вошёл, порт оставить    Esc: не вышло, вернуть старый",
    "done.title": "Готово",
    "done.rollback": "Откатить: {command}",
    # K0: shell, menu, keys
    "app.version": "версия {version}",
    "mode.reports": "Отчёты прошлых запусков",
    "app.soon": "Этот раздел появится в следующей версии KERBEROS",
    "hdr.demo": "демо",
    "hdr.mask": "маскировка",
    "keys.select": "выбор",
    "keys.toggle": "отметить",
    "keys.all": "все",
    "keys.next": "дальше",
    "keys.back": "назад",
    "keys.mask": "маскировка",
    "keys.full_report": "отчёт целиком",
    "keys.help": "помощь",
    "keys.quit": "выход",
    "keys.scroll": "прокрутка",
    "keys.skip": "пропустить",
    "keys.skip_node": "пропустить ноду",
    "keys.space": "Пробел",
    "quit.title": "Выход",
    "quit.confirm": "Выйти из KERBEROS?",
    "quit.confirm_busy": "Идут изменения. Выйти, когда текущее изменение закончится?",
    "quit.yes": "Enter: выйти",
    "quit.no": "Esc: остаться",
    "help.title": "Клавиши",
    "help.body": (
        "↑ ↓        выбор\n"
        "Пробел     отметить\n"
        "a          отметить все\n"
        "Enter      дальше\n"
        "Esc        назад, пока ничего не изменено\n"
        "m          маскировка адресов и доменов\n"
        "s          отчёт целиком\n"
        "?          эта справка\n"
        "q          выход"
    ),
    "help.close": "Любая клавиша: закрыть",
    "notice.info": "Инфо",
    "notice.warning": "Внимание",
    "notice.error": "Ошибка",
    "input.hidden": "(символы скрыты)",
    "input.invalid": "Проверьте значение: {reason}",
    "pager.position": "строки {start}–{end} из {total}",
    "risk.high": "высокий",
    "risk.medium": "средний",
    "risk.low": "низкий",
    "risk.info": "инфо",
    "score.before_after": "было {before}, стало {score}",
    "score.red": "Слабая защита",
    "score.yellow": "Защита есть, но не полная",
    "score.green": "Хорошая защита",
    "error.retry": "Enter: повторить",
    "error.back": "Esc: назад",
    "keys.field": "поле",
    # K1: S2 panel (§7)
    "s2.title": "Панель",
    "panel.searching": "Ищу панель на этом сервере…",
    "panel.choose": "Какая панель на этом сервере?",
    "panel.choose.found": "найдена, версия {version}",
    "panel.choose.none": "не найдена",
    "panel.choose.hint": (
        "С 3x-ui KERBEROS защищает этот сервер: панель и VPN на нём же. Для нескольких "
        "серверов 3x-ui запустите KERBEROS на каждом."
    ),
    "panel.xui.found": "Нашёл 3x-ui {version} на этом сервере",
    "panel.xui.port": "Панель на порту {port}",
    "panel.xui.not_found": "3x-ui на этом сервере не нашёл. Укажите адрес панели.",
    "panel.xui.url_label": "Адрес панели 3x-ui с секретным путём",
    "panel.xui.url_hint": "Например, http://127.0.0.1:2053/путь/",
    "panel.xui.url_invalid": "нужен адрес вида http://127.0.0.1:2053/путь/",
    "panel.xui.login": "Логин панели 3x-ui",
    "panel.xui.code": "Код двухфакторной проверки",
    "panel.xui.login_hint": (
        "Войдите в панель. Пароль нужен только на время входа. После пяти ошибок 3x-ui "
        "закрывает вход на 15 минут."
    ),
    "panel.xui.err.login": "Неверный логин, пароль или код",
    "panel.xui.err.forbidden": "Панель отклонила запрос: проверьте домен и версию 3x-ui",
    "panel.xui.ip_label": "Публичный IPv4 этого сервера",
    "panel.xui.ip_hint": (
        "На интерфейсах его нет: сервер за NAT. По нему KERBEROS проверяет сервер снаружи."
    ),
    "panel.xui.ip_invalid": "нужен адрес вида 203.0.113.10",
    "panel.xui.loading": "Читаю инбаунды 3x-ui…",
    "panel.xui.ok": "Панель подключена: инбаундов {inbounds}",
    "panel.kind.remnawave": "Remnawave",
    "panel.kind.3x-ui": "3x-ui",
    "panel.not_found": "Remnawave на этом сервере не нашёл. Укажите адрес API панели.",
    "panel.api_label": "Адрес API панели",
    "panel.api_hint": "Например, http://127.0.0.1:3000/api",
    "panel.api_invalid": "нужен адрес вида http://127.0.0.1:3000/api",
    "panel.api": "API: {api}",
    "panel.domain": "Домен панели: {domain}",
    "panel.login_hint": "Войдите как администратор панели. Пароль нужен только на время входа.",
    "panel.token_hint": (
        "Вход по паролю в панели выключен, поэтому нужен API-токен. "
        "Браузер понадобится только чтобы создать его в панели."
    ),
    "panel.connecting": "Подключаюсь к панели…",
    "panel.loading": "Читаю ноды, хосты и профили…",
    "panel.err.login": "Неверный логин или пароль",
    "panel.err.token": "Токен не подходит",
    "panel.err.password_off": "Вход по паролю в панели выключен",
    "panel.err.forbidden": "У токена нет прав: {operation}",
    "panel.err.server": "Панель отвечает ошибкой {status}: {operation}",
    "panel.err.timeout": "Панель не отвечает: {operation}",
    "panel.err.unreachable": "Панель не принимает соединения: {api}",
    "panel.err.no_response": (
        "Панель не ответила на {operation}. Объект мог создаться, "
        "поэтому KERBEROS не повторяет запрос."
    ),
    "panel.err.bad_request": "Панель отклонила запрос {operation}: {detail}",
    "panel.err.bad_response": (
        "Панель ответила не так, как ожидалось ({detail}). KERBEROS остановился до изменений."
    ),
    # K1: S3 nodes
    "s3.title": "Ноды",
    "nodes.col.country": "Страна",
    "nodes.col.name": "Нода",
    "nodes.col.address": "Адрес",
    "nodes.col.status": "Статус",
    "nodes.col.online": "Онлайн",
    "nodes.col.protocols": "Протоколы",
    "nodes.col.role": "Роль",
    "nodes.status.connected": "подключена",
    "nodes.status.offline": "нет связи",
    "nodes.status.disabled": "выключена",
    "nodes.role.main": "основа",
    "nodes.role.reserve": "резерв",
    "nodes.selected": "Отмечено: {n} из {total}",
    "nodes.disabled_hint": "Выключенные в панели ноды видны серыми и не выбираются.",
    "nodes.need_one": "Отметьте хотя бы одну ноду",
    # K2: S4 access to the nodes (§8)
    "access.title": "Доступ к нодам",
    "access.title.local": "Доступ к этому серверу",
    "access.intro": (
        "Чтобы проверить ноды изнутри, KERBEROS поставит на каждую свой агент (один файл) "
        "и ключ, который работает только с этого сервера. Настройки SSH, фаервола и VPN "
        "«Проверка» не меняет."
    ),
    "access.intro.local": (
        "Чтобы проверить этот сервер изнутри, KERBEROS поставит на него свой агент "
        "(один файл) и ключ, который работает только отсюда. Настройки SSH, фаервола и VPN "
        "«Проверка» не меняет."
    ),
    "access.col.node": "Нода",
    "access.col.server": "Сервер",
    "access.col.address": "Адрес",
    "access.col.status": "Доступ",
    "access.col.type": "Тип",
    "access.col.comment": "Комментарий",
    "access.col.fingerprint": "Отпечаток",
    "access.status.ok": "доступ есть",
    "access.status.none": "нет доступа",
    "access.status.denied": "пропущена",
    "access.checking_key": "Проверяю ключ сервера {node}…",
    "access.port_label": "Порт SSH для {node}",
    "access.port_hint": "К порту {port} подключиться не удалось. Укажите порт SSH этой ноды.",
    "access.port_invalid": "нужен номер порта от 1 до 65535",
    "access.yes": "Да, это мой сервер",
    "access.no": "Нет, пропустить ноду",
    "access.skip": "Пропустить ноду",
    # The command stands on a line of its own: a wrap inside it would break a copy.
    "access.hostkey_hint": (
        "Сверить можно в консоли хостера:\nssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
    ),
    "access.hostkey_same": (
        "Такой же ключ у {nodes}: так бывает у серверов из одного образа хостера."
    ),
    "access.hostkey_changed": (
        "Ключ сервера {node} изменился. Так бывает после переустановки сервера, но так же "
        "выглядит перехват соединения. Подтверждайте, только если переустанавливали сервер "
        "или меняли ключи."
    ),
    "access.hostkey_old": "Был: {fingerprint}",
    "access.hostkey_new": "Новый ключ: {fingerprint}",
    "access.accept_new": "Подтвердить новый ключ",
    "access.trying_keys": "Пробую войти ключами root сервера панели…",
    "access.installing": "Ставлю агента KERBEROS на {node}…",
    "access.installing_python": "Ставлю python3-minimal на {node}…",
    "access.no_python": "На ноде {node} нет python3. Поставить python3-minimal?",
    "access.install_python": "Поставить python3-minimal",
    "access.verify": "Проверяю вход ключом KERBEROS новым соединением…",
    "access.checking_agent": "Проверяю агента на {node}…",
    "access.updating": "Обновляю агента на {node}…",
    "access.summary": "Доступ есть у {ok} из {total:ноды|нод|нод}",
    "access.summary.local": "Доступ к этому серверу есть",
    "access.summary.local.none": (
        "Доступа к этому серверу нет: KERBEROS проверит его только со стороны панели"
    ),
    "access.panel_only": "Ноды без доступа проверяются только со стороны панели.",
    "access.reason.unreachable": "не отвечает по SSH",
    "access.reason.login": "не удалось войти",
    "access.reason.declined": "ключ сервера не подтверждён",
    "access.reason.python": "нет python3",
    "access.reason.verify": "вход ключом KERBEROS не прошёл",
    "access.reason.hostkey": "ключ сервера изменился",
    "access.reason.keygen": "не удалось создать ключ KERBEROS на сервере панели",
    "access.reason.failed": "ошибка установки: {detail}",
    "access.local.installing": "Ставлю агента KERBEROS на этот сервер…",
    "access.admin.local.some": (
        "На этом сервере есть ваши ключи ({n}): вход по паролю можно выключить."
    ),
    "access.admin.local.none": "Ваших ключей на этом сервере нет: вход по паролю останется.",
    "access.reason.local_key": "не нашёл ключ этого сервера /etc/ssh/ssh_host_ed25519_key.pub",
    "access.admin.title": "Ключ администратора",
    "access.admin.mine": "Мои ключи с сервера панели ({n})",
    "access.admin.create": "Создать ключ на сервере панели",
    "access.admin.skip": "Пропустить: вход по паролю на нодах останется",
    "access.admin.choose": "Какие ключи добавить на ноды?",
    "access.admin.later": (
        "Ключи попадут на ноды только после вашего разрешения на экране согласия."
    ),
    "access.admin.chosen.mine": "Ключ администратора: ваши ключи с сервера панели",
    "access.admin.chosen.create": "Ключ администратора: KERBEROS создаст его на сервере панели",
    "access.admin.chosen.skip": "Ключ администратора: пропущен, вход по паролю на нодах останется",
    "ssh.unknown_node": "Нода {node} не найдена: сначала дайте KERBEROS доступ к ней",
    "ssh.no_admin_key": (
        "Ключа администратора на сервере панели нет. Его создаёт «Исправление», "
        "если на экране доступа выбрать «Создать ключ на сервере панели»."
    ),
    "ssh.demo": "В демо входа на ноды нет: ноды встроенного парка не настоящие",
    "lock.busy": "KERBEROS уже запущен в другом окне. Дождитесь его завершения.",
    # K3: topics, findings and actions (§10.2)
    "topic.hosting": "Хостинг и AS",
    "topic.sni": "Свой SNI вместо чужого",
    "topic.scanning": "Защита от сканирования",
    "topic.dpi": "DPI",
    "topic.routing": "Умная маршрутизация",
    "topic.reserves": "Резервы",
    "target.panel": "панель",
    "target.fleet": "парк",
    "target.template": "шаблон {name}",
    "target.host": "хост {name}",
    "action.fix": "Исправит KERBEROS",
    "action.manual": "Вручную: {how}",
    "action.explain": "Объяснение: {how}",
    "action.plan": "{how}",
    "action.passed": "Пройдено",
    "action.partial": "Вручную: паддинг настроен частично, его правят руками",
    "check.fleet.same_asn.title": "Ноды одной страны у одного хостера (AS{asn})",
    "check.fleet.same_asn.threat": "Блокировку по AS хостера получат сразу все такие ноды",
    "check.fleet.same_asn.how": "держите резерв у другого хостера",
    "check.fleet.same_24.title": "Ноды в одной или соседних подсетях /24 ({net})",
    "check.fleet.same_24.threat": "Блокировка подсети снимет сразу несколько нод",
    "check.fleet.same_24.how": "разнесите ноды по разным подсетям или хостерам",
    "check.fleet.shared_hostkey.title": "Одинаковый ключ сервера у нескольких нод",
    "check.fleet.shared_hostkey.threat": (
        "Сканеры собирают ключи SSH и по ним связывают ваши серверы между собой"
    ),
    "check.fleet.one_zone.title": "Домены трёх и больше нод в одной зоне {zone}",
    "check.fleet.one_zone.threat": (
        "Сертификаты попадают в публичные журналы CT, и по зоне находят все ноды разом"
    ),
    "check.fleet.one_zone.how": "разнесите домены по разным зонам или возьмите wildcard-сертификат",
    "check.host.ip_check.title": "Блокировку IP нельзя проверить из-за рубежа",
    "check.host.ip_check.threat": "Новый IP может быть уже заблокирован у российских операторов",
    "check.host.ip_check.how": (
        "до ввода нового IP проверьте его из России у нескольких операторов"
    ),
    "check.reality.foreign_sni.title": "Reality маскируется под чужой сайт",
    "check.reality.foreign_sni.threat": (
        "Чужое имя на IP хостинга заметно: такие ноды блокируют за минуты"
    ),
    "check.probe.no_sni.title": "По IP без имени отдаётся чужой сертификат или нет сайта",
    "check.probe.no_sni.threat": "Любой, кто зайдёт на IP, поймёт, что это не обычный сайт",
    "check.hy2.foreign_masquerade.title": "Hysteria2 маскируется под чужой сайт",
    "check.hy2.foreign_masquerade.threat": "Ответ сервера не совпадает с его IP и сертификатом",
    "check.profile.template.title": "Конфиг ноды отличается от проверенного",
    "check.profile.template.threat": (
        "Reality, Hysteria2, DNS или правила настроены не так, как на проверенном парке"
    ),
    "check.site.same_template.title": "Одинаковые сайты-заглушки на нескольких нодах",
    "check.site.same_template.threat": "По одинаковой странице сканер связывает ноды между собой",
    "check.ssh.password.title": "Вход на сервер по паролю",
    "check.ssh.password.threat": (
        "Пароль перебирают тысячи раз в сутки; удачный подбор отдаёт сервер целиком"
    ),
    "check.ssh.port_default.title": "SSH на стандартном порту 22",
    "check.ssh.port_default.threat": "Сканеры находят сервер по порту 22 и начинают перебор",
    "check.ssh.fail2ban.title": "Нет защиты от перебора паролей (fail2ban)",
    "check.ssh.fail2ban.threat": "Перебор паролей SSH ничем не ограничен",
    "check.kernel.mptcp.title": "В ядре включён MPTCP",
    "check.kernel.mptcp.threat": "Уязвимость CVE-2026-98432 даёт удалённый root через MPTCP",
    "check.node_api.public.title": "Порт API ноды открыт всем",
    "check.node_api.public.threat": (
        "По TLS с обязательным клиентским сертификатом сканер узнаёт ноду Remnawave"
    ),
    "check.ports.public.title": "Открыты лишние порты: {ports}",
    "check.ports.public.threat": "Голый VLESS или XHTTP опознают по ответу на мусорный запрос",
    "check.cdn.origin_direct.title": "Сервер за CDN отвечает туннелем напрямую по IP",
    "check.cdn.origin_direct.threat": (
        "Прямой запрос к IP выдаёт туннель: CDN больше не прячет сервер"
    ),
    "check.panel.public.title": "Панель открыта на публичном домене без барьера",
    "check.panel.public.threat": "Страницу входа находят сканеры и подбирают пароль",
    "check.panel.public.how": (
        "закройте панель барьером: caddy-security, секретный путь или доступ по VPN"
    ),
    "check.xui.panel_exposed.title": "Панель 3x-ui открыта всем на порту {port}",
    "check.xui.panel_exposed.threat": (
        "Сканеры находят панель по порту и странице входа, а через неё весь сервер"
    ),
    "check.xui.panel_exposed.how": (
        "в настройках 3x-ui смените порт, задайте секретный путь и сертификат; надёжнее "
        "слушать только 127.0.0.1 и входить через SSH-туннель"
    ),
    "check.panel_server.ssh.title": "На сервер панели можно войти по паролю",
    "check.panel_server.ssh.threat": "Взлом сервера панели отдаёт управление всеми нодами",
    "check.panel_server.ssh.how": (
        "выключите вход по паролю сами: KERBEROS не меняет доступ к серверу, "
        "на котором вы работаете"
    ),
    "check.client.ping_type.title": "Клиенты меряют задержку прямым пингом до IP ноды",
    "check.client.ping_type.threat": (
        "Прямые ICMP и TCP на IP ноды выделяются на фоне обычного трафика"
    ),
    "check.node.icmp.title": "Нода отвечает на ping",
    "check.node.icmp.threat": "",
    "check.node.icmp.how": (
        "выключать не нужно: важнее тип пинга клиента, а ping нужен для диагностики"
    ),
    "check.xhttp.padding.title": "У XHTTP нет паддинга",
    "check.xhttp.padding.threat": "Размеры запросов складываются в узнаваемую сигнатуру",
    "check.xhttp.uplink_get.title": "XHTTP за CDN отправляет данные методом POST",
    "check.xhttp.uplink_get.threat": "Российские CDN режут POST: наблюдали ответ 405",
    "check.xhttp.post_size.title": (
        "Маленький scMaxEachPostBytes у хоста за CDN ({scMaxEachPostBytes})"
    ),
    "check.xhttp.post_size.threat": "",
    "check.xhttp.post_size.how": (
        "запросов к CDN становится в разы больше, они упираются в лимит на соединение; "
        "держите не меньше 10 000"
    ),
    "check.xhttp.extra_outer.title": "Параметры sc* XHTTP стоят вне extra",
    "check.xhttp.extra_outer.threat": "Xray молча игнорирует их, когда задан extra",
    "check.xhttp.extra_outer.how": "перенесите параметры sc* внутрь extra",
    "check.host.fingerprint.title": "У хоста {host} пустой fingerprint",
    "check.host.fingerprint.threat": "Клиент шлёт ClientHello, не похожий на браузер",
    "check.dpi.fragment.title": "Фрагментация ClientHello не нужна",
    "check.dpi.fragment.threat": "",
    "check.dpi.fragment.how": "со своим доменом SNI совпадает с IP: резать нечего",
    "check.dpi.mtu.title": "MTU 1280 на сервере не меняем",
    "check.dpi.mtu.threat": "",
    "check.dpi.mtu.how": "MTU настраивают в клиенте, а не на сервере",
    "check.sub.ru_direct.title": "Российские сайты идут через ноду (шаблон {template})",
    "check.sub.ru_direct.threat": ("Сайты в РФ видят IP ноды, а нода копит подозрительный трафик"),
    "check.sub.probe_interval.title": "Клиент проверяет ноды чаще раза в минуту ({seconds} с)",
    "check.sub.probe_interval.threat": "Частые пробы заметны и тратят трафик",
    "check.exit.ru_traffic.title": "Через ноду ходят российские сайты ({ruShare})",
    "check.exit.ru_traffic.threat": "Доля российских доменов в трафике ноды выше 1 %",
    "check.exit.ru_traffic.how": "исправится шаблоном подписки KERBEROS (sub.template)",
    "check.reserve.missing.title": "У ноды нет скрытого резерва",
    "check.reserve.missing.threat": (
        "При блокировке клиенты останутся без связи, пока не обновят подписку"
    ),
    "check.reserve.missing.how": "резервную ноду выбирают в плане исправления",
    "check.reserve.same_asn.title": "Основа и резерв у одного хостера (AS{asn})",
    "check.reserve.same_asn.threat": "Блокировка хостера снимет и основу, и резерв",
    "check.reserve.same_asn.how": "держите резерв у другого хостера",
    "check.node.blocked.title": "Похоже, ноду заблокировали",
    "check.node.blocked.threat": (
        "На основе нет пользователей, а резерв работает, или соединения обрываются"
    ),
    "check.node.blocked.how": "замените IP основы у хостера",
    "check.watch.missing.title": "Нет сборщика признаков блокировки",
    "check.watch.missing.threat": "Блокировку видно только по жалобам пользователей",
    # K3: S5 collection and S6 report
    "s5.title": "Проверка",
    "s5.collecting": "Собираю данные: только чтение, ничего не меняю",
    "s5.col.node": "Нода",
    "s5.step.facts": "факты",
    "s5.step.watch": "наблюдение",
    "s5.step.site": "сайт",
    "s5.step.outside": "снаружи",
    "s5.whois.question": (
        "Узнать хостеров (AS) нод через whois.cymru.com? "
        "Запрос передаст адреса нод третьей стороне."
    ),
    "s5.whois.yes": "Да, узнать AS",
    "s5.whois.no": "Нет, без whois",
    "s5.failed": "Сбор данных остановился: {error}",
    "s6.title": "Отчёт проверки",
    "s6.summary": "Найдено: {problems}. Исправит KERBEROS: {auto}. Вручную: {manual}.",
    "s6.none": "Проблем не найдено",
    "s6.details": "Пробел: подробности",
    "s6.end": "Enter: в меню",
    "s6.next": "Enter: к плану исправления",
    "s6.no_access": "Без доступа, проверены только со стороны панели: {nodes}",
    "keys.details": "подробности",
    "keys.menu": "в меню",
    "report.title.check": "KERBEROS: отчёт проверки",
    "report.title.fix": "KERBEROS: отчёт исправления",
    "report.title.rollback": "KERBEROS: отчёт отката",
    "report.title.finalize": "KERBEROS: отчёт финализации",
    "report.head": "Время: {time} · Режим: {mode} · Панель: Remnawave {version} · Нод: {nodes}",
    "report.mode.check": "Проверка",
    "report.mode.fix": "Исправление",
    "report.mode.rollback": "Откат",
    "report.mode.finalize": "Финализация",
    "report.score_before_after": "Защищённость: было {before}, стало {after} из 100",
    "report.threat": "Чем грозит: {text}",
    "report.details": "Подробности: {text}",
    "report.passed": "Пройдено проверок: {n}",
    "report.nodes": "Ноды",
    "report.nodes.head": "| Нода | Адрес | Порт SSH | Доступ |",
    "report.rollback": "Откат",
    "report.empty": "Отчётов пока нет: запустите «Проверку» или «Исправление».",
    "reports.title": "Отчёты",
    "reports.item": "{run} · {mode} · защищённость {score}",
    # K4: S7 plan, consent, S8 applying, S9 report, rollback
    "fix.access.admin_keys.label": "Добавить ваш ключ администратора",
    "fix.mptcp.guard.label": "Выключить MPTCP, отбрасывать IP-опции",
    "fix.fail2ban.sshd.label": "Защитить SSH от перебора (fail2ban)",
    "fix.node_api.panel_only.label": "Открыть API ноды только панели",
    "fix.ports.drop.label": "Закрыть лишние порты: {ports}",
    "fix.hostkeys.regenerate.label": "Новые ключи сервера",
    "fix.ssh.key_only.label": "Вход только по ключу",
    "fix.ssh.port.label": "Перенести SSH на порт {port}",
    "fix.self_steal.label": "Свой домен {domain}",
    "fix.self_steal.site.label": "Сайт и сертификат на {domain}",
    "fix.node.letsencrypt_mount.label": "Сертификат виден контейнеру ноды",
    "fix.self_steal.profile.label": "Профиль ноды по шаблону KERBEROS на {domain}",
    "fix.self_steal.squads.label": "Новый инбаунд в сквадах",
    "fix.self_steal.hosts.label": "Копии хостов с SNI {domain}, старые выключены",
    "fix.sub.templates.label": "Шаблоны подписки KERBEROS в панели",
    "fix.sub.template.label": "Хосты на шаблон подписки KERBEROS",
    "fix.sub.ping_type.label": "Пинг клиентов через туннель (ping-type)",
    "fix.host.fingerprint.label": "Fingerprint firefox у хоста",
    "fix.reserve.label": "Резерв {reserve}: скрытые хосты с общими тегами",
    # K10: a stub site of its own on every node
    "plan.site": "Сайт для {node}: «{title}», {kind}",
    "plan.site.again": "g: другой сайт",
    "s9.site": "Сайт «{title}» ({kind}), цвета {background} и {accent}",
    "report.site": "Сайт «{title}» ({kind}), цвета {background} и {accent}",
    "site.kind.bakery": "пекарня",
    "site.kind.coffee": "обжарка кофе",
    "site.kind.bikes": "веломастерская",
    "site.kind.photo": "фотостудия",
    "site.kind.translate": "бюро переводов",
    "site.kind.architecture": "архитектурное бюро",
    "site.kind.pottery": "керамическая мастерская",
    "site.kind.tea": "чайная",
    "site.kind.bindery": "переплётная мастерская",
    "site.kind.garden": "ландшафтный дизайн",
    "site.kind.wood": "столярная мастерская",
    "site.kind.music": "музыкальная школа",
    "site.kind.tailor": "ателье",
    "site.kind.yoga": "студия йоги",
    # K8: XHTTP, CDN origin, watch
    "fix.cdn.edge_only.label": "Туннель на origin только через CDN",
    "fix.watch.install.label": "Сборщик признаков блокировки",
    "fix.xhttp.padding.label": "Паддинг XHTTP на сервере и в подписке",
    "fix.xhttp.uplink_get.label": "Загрузка через CDN методом GET",
    "fix.edge_only.warning": (
        "Origin будет пускать к туннелю только подтверждённые сети CDN, прямой запрос получит "
        "ответ несуществующей страницы. Если CDN придёт с новой сети, клиенты через неё не "
        "подключатся, пока сеть не добавят."
    ),
    "fix.padding.warning": (
        "Паддинг XHTTP изменится на сервере и в подписке. Клиенты, которые не обновят "
        "подписку, не подключатся через XHTTP, пока не обновят её."
    ),
    "keys.edges": "сети CDN",
    "plan.edges.none": "e: выберите сети CDN",
    "plan.edges.ok": "сетей CDN: {n} ✓",
    "plan.edges.title": "Откуда CDN ходит на {node}",
    "plan.edges.hint": (
        "Сети /24, с которых шли запросы к пути туннеля (логи nginx). Отметьте сети CDN: "
        "остальным origin ответит как несуществующая страница."
    ),
    "plan.edges.col.net": "Сеть",
    "plan.edges.col.count": "Запросов",
    "plan.edges.empty": (
        "В логах nginx нет запросов к пути туннеля: список сетей CDN составить не из чего."
    ),
    "plan.edges.failed": "Не удалось прочитать логи nginx на ноде: {reason}",
    "plan.edges.confirm": "подтвердить отмеченные",
    "plan.need_edges": "Подтвердите сети CDN (клавиша e) или снимите отметку с фильтра CDN",
    "plan.blocked.realip_enabled": "включён real_ip",
    "error.realip_enabled": "в nginx включён real_ip",
    "error.bad_response": "панель ответила не по схеме",
    "keys.reserve": "резерв",
    "plan.reserve.with": "резерв: {node}",
    "plan.reserve.of": "резерв для {node}",
    "plan.need_reserve": (
        "У пары основа–резерв обе ноды должны переходить на свой домен в этом запуске"
    ),
    "keys.domain": "домен",
    "plan.domain.label": "Домен для {node}",
    "plan.domain.hint": "A-запись домена должна указывать на IP ноды",
    "plan.domain.invalid": "нужен домен вида node.example.com",
    "plan.domain.none": "d: введите домен",
    "plan.domain.wait": "Ждёт DNS: нужна запись {record}. Проверяю раз в 10 секунд.",
    "plan.domain.waiting": "ждёт DNS",
    "plan.domain.ok": "домен {domain} ✓",
    "plan.need_domain": (
        "У отмеченного self-steal нет домена с верной A-записью: введите домен (d) "
        "или снимите отметку"
    ),
    "plan.blocked.node_offline": "нода не подключена к панели",
    "plan.blocked.no_profile": "у ноды нет профиля",
    "plan.blocked.shared_profile": "профиль общий с другими нодами: нужен свой профиль",
    "plan.blocked.port80_busy": "порт 80 занят не nginx",
    "plan.blocked.port443": "порт 443 держит не Xray",
    "plan.finalize.manual": "Старые имена уберёт kerberos finalize через сутки (f: автоматически)",
    "plan.finalize.auto": "Старые имена уберутся автоматически через сутки (f: вручную)",
    "plan.finalize.xui": (
        "Старые имена уберёт kerberos finalize через сутки. До этого 3x-ui даёт в новых ссылках "
        "случайное имя из serverNames, после финализации клиентам нужно обновить подписку."
    ),
    "fix.xui.reality.label": "Reality-инбаунды 3x-ui на домен {domain}",
    "error.no_reality": "в 3x-ui нет включённого Reality-инбаунда",
    "s9.hosts": (
        "Копий хостов: {created}, выключено старых: {disabled}. Копии стоят в конце списка."
    ),
    "s9.finalize": "Через сутки уберите старые имена: {command}",
    "s9.finalize.auto": "Старые имена уберутся сами через сутки (таймер на сервере панели)",
    "error.port80_busy": "порт 80 занят не nginx",
    "error.certbot_failed": "сертификат не выпустился",
    "error.nginx_test_failed": "nginx -t не принял конфиг",
    "error.check_failed": "проверка снаружи не увидела свой домен",
    "error.node_offline": "нода не подключилась к панели после смены профиля",
    "error.host_mismatch": "панель сохранила копию хоста не так, как её отправили",
    "error.changed_in_panel": "объект в панели изменён после KERBEROS",
    "error.no_panel": "нет доступа к панели",
    "error.no_snapshot": "нет снимка объекта до изменения",
    "error.gone": "объекта больше нет в панели",
    "rb.diff.intro": "Этот объект в панели изменили после KERBEROS. Различия:",
    "tpl.diff.intro": "Шаблон KERBEROS в панели правили руками. Чем он отличается от проверенного:",
    "tpl.diff.question": "Записать проверенный шаблон поверх ручных правок?",
    "rb.diff.question": "Откатить всё равно? Ручные правки пропадут.",
    "mode.finalize": "Завершить self-steal: убрать старые имена",
    "app.pending": "Есть незавершённое: убрать старое имя у {n} нод",
    "fin.title": "Финализация",
    "fin.none": "Завершать пока нечего: сутки ещё не прошли или self-steal не было.",
    "fin.consent": (
        "Старые имена уйдут из serverNames. Клиенты без новой подписки перестанут подключаться:"
    ),
    "fin.accept": "Убрать старые имена",
    "fin.done": "Готово: старые имена убраны у {n} нод",
    "fin.failed": "Не получилось у {n} нод: подробности в отчёте",
    "error.port_closed": (
        "новый порт не открылся, похоже, его закрывает фаервол хостера: откройте порт "
        "в панели хостера; KERBEROS вернул старый"
    ),
    "error.port_busy": "этот порт уже занят на ноде",
    "s9.ssh_port": "Новый порт SSH: {port}",
    "s9.login": "Входить теперь: {command} или kerberos ssh {node}",
    "report.ssh_port": "Новый порт SSH: {port}. Входить: {command}",
    "plan.col.node": "Нода",
    "plan.col.fix": "Исправление",
    "plan.col.risk": "Риск",
    "plan.col.note": "Заметка",
    "plan.blocked.no_admin_key": "нет ключа администратора: вход по паролю останется",
    "plan.blocked.bridge_network": "нода в сети Docker bridge: правило не сработает",
    "plan.has_warning": "предупреждение",
    "plan.empty": "Автоматически исправлять нечего. Что сделать вручную, написано в отчёте.",
    "plan.selected": "Отмечено: {n} из {total}",
    "consent.intro": "Что изменится:",
    "consent.keys": "Enter: разрешить. Любая другая клавиша: вернуться к плану",
    "s8.title": "Применение",
    "step.backup": "бэкап",
    "step.apply": "применение",
    "step.check": "проверка",
    "step.confirm": "подтверждение",
    "board.node": "Нода",
    "board.fix": "Исправление",
    "board.legend": "✓ готово · … идёт · ✗ ошибка · ↺ откачено · – не нужно",
    "keys.interrupt": "прервать",
    "apply.interrupt": (
        "Прервать? Текущее изменение KERBEROS доведёт до конца или откатит, новые не начнутся."
    ),
    "apply.interrupted": "Прервано: новые изменения не начинались",
    "s9.hostkey": (
        "Новый ключ сервера: {fingerprint}. Кто входил на него раньше: ssh-keygen -R {address}"
    ),
    "s9.none": "Ничего не изменилось",
    "state.planned": "в плане",
    "state.applying": "применялось",
    "state.applied": "применено",
    "state.pending_confirm": "ждёт подтверждения",
    "state.confirmed": "применено и подтверждено",
    "state.failed": "не применено",
    "state.rolled_back": "откачено",
    "error.confirm_failed": "новое соединение не подтвердило доступ",
    "error.recheck_failed": "после изменения проверка не прошла",
    "error.no_admin_key": "нет ключа администратора",
    "error.bridge_network": "нода в сети Docker bridge",
    "error.docker_published": "порт опубликован Docker",
    "error.sshd_test_failed": "sshd -t не принял конфиг",
    "error.apt_failed": "не поставились пакеты",
    "error.mptcp_absent": "в ядре нет MPTCP",
    "error.change_conflict": "файл изменён позже: сначала откатите более позднее изменение",
    "error.command_failed": "команда на ноде не выполнилась",
    "error.no_backup": "на ноде нет бэкапа этого изменения",
    "error.backup_damaged": "бэкап на ноде повреждён",
    "error.timeout": "нода не ответила",
    "error.refused": "нода не принимает соединения",
    "error.unreachable": "нода недоступна",
    "error.auth": "ключ KERBEROS не подошёл",
    "error.hostkey_changed": "ключ сервера изменился",
    "error.failed": "сбой SSH",
    "rb.title": "Откат",
    "rb.choose": "Какой запуск откатить?",
    "rb.item": "{run} · изменений: {n}",
    "rb.changes": "Что откатить",
    "rb.col.change": "Изменение",
    "rb.col.state": "Состояние",
    "rb.consent": "Откатятся изменения ({n}) в обратном порядке:",
    "rb.accept": "Откатить изменения",
    "rb.empty": "Откатывать нечего: нет запусков с действующими изменениями.",
    "rb.done": "Откачено: {ok} из {total}",
    "rb.failed": "Часть изменений не откатилась. Что проверить руками, написано в отчёте.",
    "report.changes": "Изменения",
    "report.change": "- {state} · {node} · {fix}",
    "report.change_error": "  - Причина: {reason}",
    "report.backups": "Бэкапы на нодах: /var/lib/kerberos/changes/<changeId>/",
    # CLI (§5.3)
    "cli.usage": "Использование: sudo ./kerberos [команда] [флаги]",
    "cli.help": (
        "KERBEROS: защита VPN-серверов на Remnawave и 3x-ui\n"
        "\n"
        "Использование: sudo ./kerberos [команда] [флаги]\n"
        "\n"
        "Команды:\n"
        "  (без команды)      меню: Проверка, Исправление, Откат, Отчёты\n"
        "  check              сразу режим «Проверка»\n"
        "  fix                сразу режим «Исправление»\n"
        "  rollback [runId]   откат запуска или отдельных изменений\n"
        "  report [runId]     показать отчёт; без терминала печатает report.md\n"
        "  finalize [runId]   завершить отложенные шаги self-steal\n"
        "  ssh <нода>         войти на ноду ключом администратора\n"
        "\n"
        "Флаги:\n"
        "  --demo       весь сценарий на встроенном парке, без панели и серверов\n"
        "  --mask       заменить адреса и домены примерами из документации\n"
        "  --panel P    панель без вопроса: remnawave или 3x-ui\n"
        "  --no-color   без цвета (также переменная NO_COLOR)\n"
        "  --help       эта справка\n"
        "  --version    версия\n"
        "\n"
        "Коды выхода: 0 готово; 2 неверные аргументы; 3 нет доступа к панели;\n"
        "4 часть изменений не применилась и откачена; 5 откат не удался, нужна ручная\n"
        "проверка; 130 прервано, незавершённые изменения откачены."
    ),
    "cli.bad_args": "Неверные аргументы: {detail}",
    "cli.unknown_flag": "неизвестный флаг {flag}",
    "cli.bad_panel": "--panel: нужно remnawave или 3x-ui, а не «{value}»",
    "cli.unknown_command": "неизвестная команда {command}",
    "cli.extra_arg": "лишний аргумент {arg}",
    "cli.missing_node": "укажите ноду: kerberos ssh <нода>",
    "cli.no_tty": "Запустите KERBEROS в терминале",
    "cli.version": "KERBEROS {version}",
    "cli.interrupted": "Прервано.",
}


def plural(n: int, one: str, few: str, many: str) -> str:
    """The form of a Russian word after the number `n`: 1 нода, 3 ноды, 5 нод, 11 нод."""
    n = abs(n)
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


class _Count(int):
    """A number that formats `{n:нода|ноды|нод}` as the number and the word after it."""

    def __format__(self, spec: str) -> str:
        if "|" not in spec:
            return format(int(self), spec)
        one, few, many = spec.split("|")
        return f"{int(self)} {plural(int(self), one, few, many)}"


def t(key: str, **params: object) -> str:
    """Return the text for `key` with `params` substituted."""
    text = TEXT[key]
    if not params:
        return text
    counted = {k: _Count(v) if type(v) is int else v for k, v in params.items()}
    return text.format(**counted)
