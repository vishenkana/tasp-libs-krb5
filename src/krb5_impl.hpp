/**
 * @file
 * @brief Реализация интерфейсов для работы с аутентификацией Kerberos.
 */
#ifndef TASP_KRB5_IMPL_HPP_
#define TASP_KRB5_IMPL_HPP_

#include <krb5.h>

#include <memory>
#include <mutex>
#include <string_view>

namespace tasp::krb5
{

/**
 * @brief Базовый класс для всех классов работы с Kerberos.
 */
class Context
{
public:
    /**
     * @brief Конструктор.
     * 
     * @param context Главная структура библиотеки Kerberos
     */
    explicit Context(const std::shared_ptr<_krb5_context> &context) noexcept;

    /**
     * @brief Деструктор.
     */
    virtual ~Context() noexcept;

    Context(const Context &) = delete;
    Context(Context &&) = delete;
    Context &operator=(const Context &) = delete;
    Context &operator=(Context &&) = delete;

protected:
    /**
     * @brief Получение указателя на структуру главной библиотеки Kerberos.
     *
     * @return Указатель на структуру
     */
    inline _krb5_context *GetContext() const noexcept;

    /**
     * @brief Получение умного указателя на структуру главной библиотеки Kerberos.
     *
     * @return Умный указатель на структуру
     */
    inline std::shared_ptr<_krb5_context> GetContextPtr() const noexcept;

    /**
     * @brief Ввод сообщения об ошибке в глобальный лог.
     *
     * @param code Код ошибки от вызова функции бибилиотеки Kerberos
     * @param message Сопровождающее сообщение к коду ошибки
     */
    void PrintError(krb5_error_code code,
                    std::string_view message) const noexcept;

private:
    /**
     * @brief Главная структура библиотеки Kerberos.
     */
    std::shared_ptr<_krb5_context> context_;
};

/**
 * @brief Класс для работы c уникальным именем клиента Kerberos.
 */
class Principal : public Context final
{
public:
    /**
     * @brief Конструктор.
     * 
     * @param context Главная структура библиотеки Kerberos
     * @param principal Структура с уникальным именем клиента библиотеки
     */
    Principal(const std::shared_ptr<_krb5_context> &context,
                  krb5_const_principal principal) noexcept;

    /**
     * @brief Деструктор.
     */
    ~Principal() noexcept override;

    /**
     * @brief Запрос названия области клиента Kerberos.
     *
     * @return Название области
     */
    std::string_view Realm() const noexcept;

    /**
     * @brief Оператор для получения указателя на структуру с уникальным
     * именем клиента.
     *
     * @return Указатель на структуру
     */
    krb5_principal Ptr() const noexcept;

    Principal(const Principal &) = delete;
    Principal(Principal &&) = delete;
    Principal &operator=(const Principal &) = delete;
    Principal &operator=(Principal &&) = delete;

private:
    /**
     * @brief Структура с уникальным именем клиента.
     */
    krb5_principal principal_{nullptr};
};

/**
 * @brief Класс для работы с учетными данными Kerberos.
 */
class Creds : public Context final
{
public:
    /**
     * @brief Конструктор.
     * 
     * @param context Главная структура библиотеки Kerberos
     * @param creds Структура с учетными данными библиотеки Kerberos
     */
    Creds(const std::shared_ptr<_krb5_context> &context,
              krb5_creds creds) noexcept;

    /**
     * @brief Деструктор.
     */
    ~Creds() noexcept override;

    /**
     * @brief Статусы состояния учетных записей.
     */
    enum class State
    {
        None,  /*!< Обновлять билет не требуется */
        Renew, /*!< Необходимо продлить билет */
        Reinit /*!< Необходимо запросить новый билет */
    };

    /**
     * @brief Запрос текущего состояния учетной записи.
     *
     * @return Текущее состояние
     */
    State State() const noexcept;

    /**
     * @brief Запрос времени начала действия билета.
     *
     * @return Время начала
     */
    krb5_timestamp StartTime() const noexcept;

    /**
     * @brief Запрос времени конца действия билета.
     *
     * @return Время конца
     */
    krb5_timestamp EndTime() const noexcept;

    /**
     * @brief Запрос времени до какого можно продлять билет.
     *
     * @return Время продления
     */
    krb5_timestamp RenewTime() const noexcept;

    /**
     * @brief Формирование строки с информацией о временах билета.
     *
     * @return Сформированная строка
     */
    std::string TimesInfo() const noexcept;

    /**
     * @brief Конвертирование unix-времени в строку с датой и временем.
     * 
     * @param timestamp Unix-время
     * 
     * @return Сформированная строка
     */
    static std::string TimeToString(krb5_timestamp timestamp) noexcept;

    /**
     * @brief Получение указателя на структуру с учетными данными библиотеки Kerberos.
     *
     * @return Указатель на структуру
     */
    krb5_creds *Ptr() noexcept;

    Creds(const Creds &) = delete;
    Creds(Creds &&) = delete;
    Creds &operator=(const Creds &) = delete;
    Creds &operator=(Creds &&) = delete;

private:
    /**
     * @brief Структура с учетными данными.
     */
    krb5_creds creds_;
};

/**
 * @brief Общий интерфейс для работы с файлами Kerberos.
 */
class FileInterface : public Context
{
public:
    /**
     * @brief Конструктор.
     * 
     * @param context Главная структура библиотеки Kerberos
     * @param fullpath Полный путь к файлу.
     */
    FileInterface(const std::shared_ptr<_krb5_context> &context,
                      std::string_view fullpath) noexcept;

    /**
     * @brief Деструктор.
     */
    ~FileInterface() noexcept override;

    /**
     * @brief Проверка сущестовования файла.
     *
     * @return Результат проверки.
     */
    bool FileExists() const noexcept;

    /**
     * @brief Запрос имени файла.
     *
     * @return Имя файла
     */
    const char *FileName() const noexcept;

    /**
     * @brief Формирование учетных данных.
     *
     * @return Учетные данных Kerberos
     */
    virtual std::shared_ptr<Creds> GetCreds() const noexcept = 0;

    /**
     * @brief Получение имени клиента.
     *
     * @return Уникальное имя клиента Kerberos
     */
    virtual std::shared_ptr<Principal> GetPrincipal() const noexcept = 0;

    /**
     * @brief Полный путь к стандартному расположению файла.
     *
     * @return Полный путь
     */
    virtual std::string DefaultName() const noexcept = 0;

    /**
     * @brief Полный путь из конфигурационного файла.
     *
     * @return Полный путь
     */
    virtual std::string ConfigName() const noexcept = 0;

    FileInterface(const FileInterface &) = delete;
    FileInterface(FileInterface &&) = delete;
    FileInterface &operator=(const FileInterface &) = delete;
    FileInterface &operator=(FileInterface &&) = delete;

protected:
    /**
     * @brief Инициализация параметров.
     */
    void Init() noexcept;

    /**
     * @brief Тип запуска программы. Запуск пользователем или systemd-сервис.
     *
     * @return Тип запуска
     */
    inline std::string_view ProgramType() const noexcept;

private:
    /**
     * @brief Полный путь к файлу.
     */
    std::string fullpath_;

    /**
     * @brief Тип запуска программы.
     */
    std::string program_type_{"manual"};
};

/**
 * @brief Класс для работы с таблицей ключей Kerberos.
 */
class Keytab : public FileInterface final
{
public:
    /**
     * @brief Конструктор.
     * 
     * @param context Главная структура библиотеки Kerberos
     * @param fullpath Полный путь к таблице ключей.
     */
    Keytab(const std::shared_ptr<_krb5_context> &context,
               std::string_view fullpath) noexcept;

   /**
     * @brief Деструктор.
     */
    ~Keytab() noexcept override;

    /**
     * @brief Формирование учетных данных из таблицы ключей Kerberos.
     *
     * @return Учетные данных Kerberos
     */
    std::shared_ptr<Creds> GetCreds() const noexcept override;

    /**
     * @brief Получение имени клиента из таблицы ключей Kerberos.
     *
     * @return Уникальное имя клиента Kerberos
     */
    std::shared_ptr<Principal> GetPrincipal() const noexcept override;

    /**
     * @brief Полный путь к стандартной таблице ключей.
     *
     * @return Полный путь к таблице ключей
     */
    std::string DefaultName() const noexcept override;

    /**
     * @brief Полный путь к таблице ключей из конфигурационного файла.
     *
     * @return Полный путь к таблице ключей
     */
    std::string ConfigName() const noexcept override;

    Keytab(const Keytab &) = delete;
    Keytab(Keytab &&) = delete;
    Keytab &operator=(const Keytab &) = delete;
    Keytab &operator=(Keytab &&) = delete;

private:
    /**
     * @brief Структура таблицы ключей Kerberos.
     */
    krb5_keytab keytab_{nullptr};
};

/**
 * @brief Класс для работы с кешем учетных данных Kerberos.
 */
class Ccache : public FileInterface final
{
public:
    /**
     * @brief Конструктор.
     * 
     * @param context Главная структура библиотеки Kerberos
     * @param fullpath Полный путь к кешу учетных данных.
     */
    Ccache(const std::shared_ptr<_krb5_context> &context,
               std::string_view fullpath) noexcept;

    /**
     * @brief Деструктор.
     */
    ~Ccache() noexcept override;

    /**
     * @brief Создание кеша учетных данных с помощью уникального имени
     * клиента и учетных данных Kerberos.
     *
     * @param principal Уникальное имя клиента Kerberos
     * @param creds Учетные данных Kerberos
     * 
     * @return Результат создания
     */
    bool Create(const std::shared_ptr<Principal> &principal,
                const std::shared_ptr<Creds> &creds) const noexcept;

    /**
     * @brief Обновление кеша учетных данных Kerberos.
     *
     * @return Результат обновления
     */
    bool Update() const noexcept;

    /**
     * @brief Формирование учетных данных из кеша учетных данных Kerberos.
     *
     * @return Учетные данных Kerberos
     */
    std::shared_ptr<Creds> GetCreds() const noexcept override;

    /**
     * @brief Получение имени клиента из кеша учетных данных Kerberos.
     *
     * @return Уникальное имя клиента Kerberos
     */
    std::shared_ptr<Principal> GetPrincipal() const noexcept override;

    /**
     * @brief Получение имени сервера из кеша учетных данных Kerberos.
     *
     * @param realm Название области
     * 
     * @return Уникальное имя сервера Kerberos
     */
    std::shared_ptr<Principal> GetServerPrincipal(
        std::string_view realm) const noexcept;

    /**
     * @brief Полный путь к стандартному кешу учетных данных.
     *
     * @return Полный путь к кешу учетных данных
     */
    std::string DefaultName() const noexcept override;

    /**
     * @brief Полный путь к кешу учетных данных из конфигурационного файла.
     *
     * @return Полный путь к кешу учетных данных
     */
    std::string ConfigName() const noexcept override;

    Ccache(const Ccache &) = delete;
    Ccache(Ccache &&) = delete;
    Ccache &operator=(const Ccache &) = delete;
    Ccache &operator=(Ccache &&) = delete;

private:
    /**
     * @brief Структура кеша учетных данных Kerberos.
     */
    krb5_ccache ccache_{nullptr};
};

/**
 * @brief Интерфейс реализация для аутентификации Kerberos сервисом.
 */
class ServiceImpl final
{
public:
    /**
     * @brief Конструктор.
     */
    ServiceImpl() noexcept;

    /**
     * @brief Деструктор.
     */
    ~ServiceImpl() noexcept;

    /**
     * @brief Создание кеша учетных данных.
     *
     * @return Результат создания
     */
    [[nodiscard]] bool CreateCcache() const noexcept;

    /**
     * @brief Обновление кеша учетных данных.
     *
     * @return Результат обновления
     */
    [[nodiscard]] bool UpdateCcache() const noexcept;

    ServiceImpl(const ServiceImpl &) = delete;
    ServiceImpl(ServiceImpl &&) = delete;
    ServiceImpl &operator=(const ServiceImpl &) = delete;
    ServiceImpl &operator=(ServiceImpl &&) = delete;

private:
    /**
     * Структура таблицы ключей Kerberos.
     */
    std::unique_ptr<Keytab> keytab_{nullptr};

    /**
     * Структура с кешем учетных записей.
     */
    std::unique_ptr<Ccache> ccache_{nullptr};

    /**
     * Блокировка вызова функций из разных потоков.
     */
    mutable std::recursive_mutex mutex_{};
};

}  // namespace tasp::krb5

#endif  // TASP_KRB5_IMPL_HPP_
