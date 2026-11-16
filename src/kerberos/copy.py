"""Interface texts (tech.md §15): the only place for user-facing strings.

Keys from §15 are the mandatory minimum; tasks add their own keys additively.
`t(key, **params)` formats a text; an unknown key is a bug and raises KeyError.
"""

from __future__ import annotations

TEXT: dict[str, str] = {
    # §15 mandatory minimum
    "app.tagline": "Защита VPN-серверов на Remnawave",
    "mode.check": "Проверка: ничего не меняет",
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
    "keys.space": "Пробел",
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
    "panel.searching": "Ищу Remnawave на этом сервере…",
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
    "access.col.node": "Нода",
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
    "access.hostkey_changed": (
        "Ключ сервера {node} изменился. KERBEROS не будет к нему подключаться, "
        "пока вы не подтвердите новый ключ"
    ),
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
    "access.summary": "Доступ есть у {ok} из {total} нод",
    "access.panel_only": "Ноды без доступа проверяются только со стороны панели.",
    "access.reason.unreachable": "не отвечает по SSH",
    "access.reason.login": "не удалось войти",
    "access.reason.declined": "ключ сервера не подтверждён",
    "access.reason.python": "нет python3",
    "access.reason.verify": "вход ключом KERBEROS не прошёл",
    "access.reason.hostkey": "ключ сервера изменился",
    "access.reason.keygen": "не удалось создать ключ KERBEROS на сервере панели",
    "access.reason.failed": "ошибка установки: {detail}",
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
    # CLI (§5.3)
    "cli.usage": "Использование: sudo ./kerberos [команда] [флаги]",
    "cli.help": (
        "KERBEROS: защита VPN-серверов на Remnawave\n"
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
    "cli.unknown_command": "неизвестная команда {command}",
    "cli.extra_arg": "лишний аргумент {arg}",
    "cli.missing_node": "укажите ноду: kerberos ssh <нода>",
    "cli.no_tty": "Запустите KERBEROS в терминале",
    "cli.version": "KERBEROS {version}",
    "cli.interrupted": "Прервано.",
}


def t(key: str, **params: object) -> str:
    """Return the text for `key` with `params` substituted."""
    text = TEXT[key]
    return text.format(**params) if params else text
