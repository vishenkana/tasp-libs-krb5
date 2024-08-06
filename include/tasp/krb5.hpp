/**
 * @file
 * @brief Интерфейсы для работы с Kerberos.
 */
#ifndef TASP_KRB5_KRB5_HPP_
#define TASP_KRB5_KRB5_HPP_

#include <memory>

namespace tasp::krb5
{

class ServiceImpl;

/**
 * @brief Интерфейс для работы с глобальным объектом аутентификации Kerberos.
 *
 * Класс скрывает от пользователя реализацию с помощью идиомы PIMPL
 * (Pointer to Implementation – указатель на реализацию).
 */
class [[gnu::visibility("default")]] Service final
{
public:
    /**
     * @brief Запрос ссылки на глобальный объект аутентификации Kerberos.
     *
     * @return Ссылка на глобальный объект аутентификации Kerberos
     */
    static Service &Instance() noexcept;

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

    Service(const Service &) = delete;
    Service(Service &&) = delete;
    Service &operator=(const Service &) = delete;
    Service &operator=(Service &&) = delete;

private:
    /**
     * @brief Конструктор.
     */
    Service() noexcept;

    /**
     * @brief Деструктор.
     */
    ~Service() noexcept;

    /**
     * @brief Указатель на реализацию.
     */
    std::unique_ptr<ServiceImpl> impl_;
};

}  // namespace tasp::krb5

#endif  // TASP_KRB5_KRB5_HPP_
