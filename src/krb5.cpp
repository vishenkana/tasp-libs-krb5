#include "tasp/krb5.hpp"

#include "krb5_impl.hpp"

using std::make_unique;

namespace tasp::krb5
{
/*------------------------------------------------------------------------------
    Service
------------------------------------------------------------------------------*/
Service &Service::Instance() noexcept
{
    static Service instance;
    return instance;
}

//------------------------------------------------------------------------------
bool Service::CreateCcache() const noexcept
{
    return impl_->CreateCcache();
}

//------------------------------------------------------------------------------
bool Service::UpdateCcache() const noexcept
{
    return impl_->UpdateCcache();
}

//------------------------------------------------------------------------------
Service::Service() noexcept
: impl_(make_unique<ServiceImpl>())
{
}

//------------------------------------------------------------------------------
Service::~Service() noexcept = default;

}  // namespace tasp::krb5
