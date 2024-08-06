#include "krb5_impl.hpp"

#include "tasp/config.hpp"
#include "tasp/logging.hpp"


using std::array;
using std::make_shared;
using std::make_unique;
using std::shared_ptr;
using std::string;
using std::string_view;

namespace fs = std::experimental::filesystem;

using CMC::configGlobal;
using CMC::logGlobal;

namespace tasp::krb5
{

/*------------------------------------------------------------------------------
    Context
------------------------------------------------------------------------------*/
Context::Context(const shared_ptr<_krb5_context> &context) noexcept
: context_(context)
{
}

//------------------------------------------------------------------------------
Context::~Context() noexcept = default;

//------------------------------------------------------------------------------
_krb5_context *Context::GetContext() const noexcept
{
    return context_.get();
}

//------------------------------------------------------------------------------
shared_ptr<_krb5_context> Context::GetContextPtr() const noexcept
{
    return context_;
}

//------------------------------------------------------------------------------
void Context::PrintError(krb5_error_code code, string_view message) const noexcept
{
    const char *krb5_message = krb5_get_error_message(context(), code);

    Logging::Error("Ошибка Kerberos ({}): {}", message, krb5_message);

    krb5_free_error_message(context(), krb5_message);
}

/*------------------------------------------------------------------------------
    Principal
------------------------------------------------------------------------------*/
Principal::Principal(const shared_ptr<_krb5_context> &context,
                             krb5_const_principal principal) noexcept
: Context(context)
{
    auto error_code =
        krb5_copy_principal(Context::GetContext(), principal, &principal_);
    if (error_code != 0)
    {
        printError(error_code, "krb5_copy_principal");
    }
}

//------------------------------------------------------------------------------
Principal::~Principal()
{
    krb5_free_principal(context(), principal_);
}

//------------------------------------------------------------------------------
string_view Principal::Realm() const noexcept
{
    return principal_->realm.data;
}

//------------------------------------------------------------------------------
krb5_principal Principal::Ptr() const noexcept
{
    return principal_;
}

/*------------------------------------------------------------------------------
    Creds
------------------------------------------------------------------------------*/
Creds::Creds(const shared_ptr<_krb5_context> &context,
                     krb5_creds creds) noexcept
: Context(context)
, creds_(creds)
{
}

//------------------------------------------------------------------------------
Creds::~Creds() noexcept
{
    krb5_free_cred_contents(context(), &creds_);
}

//------------------------------------------------------------------------------
Creds::State Creds::State() const noexcept
{
    State result{State::None};

    krb5_timestamp now{0};
    krb5_timeofday(GetContext(), &now);
    if (now >= EndTime())
    {
        result = now >= RenewTime() ? State::Reinit : State::Renew;
    }

    return result;
}

//------------------------------------------------------------------------------
krb5_timestamp Creds::StartTime() const noexcept
{
    return creds_.times.starttime;
}

//------------------------------------------------------------------------------
krb5_timestamp Creds::EndTime() const noexcept
{
    return creds_.times.endtime;
}

//------------------------------------------------------------------------------
krb5_timestamp Creds::RenewTime() const noexcept
{
    return creds_.times.renew_till;
}

//------------------------------------------------------------------------------
string Creds::TimesInfo() const noexcept
{
    krb5_timestamp now{0};
    krb5_timeofday(GetContext(), &now);

    string text{};
    text.append("now: ").append(TimeToString(now)).append("\n");
    text.append("start time: ").append(TimeToString(StartTime())).append("\n");
    text.append("end time: ").append(TimeToString(SndTime())).append("\n");
    text.append("renew possible until: ").append(TimeToString(RenewTime()));

    return text;
}

//------------------------------------------------------------------------------
string Creds::TimeToString(krb5_timestamp timestamp) noexcept
{
    array<char, 256> datetime{};
    krb5_timestamp_to_string(timestamp, datetime.data(), 256);

    return datetime.data();
}

//------------------------------------------------------------------------------
krb5_creds *Creds::Ptr() noexcept
{
    return &creds_;
}

/*------------------------------------------------------------------------------
    FileInterface
------------------------------------------------------------------------------*/
FileInterface::FileInterface(const shared_ptr<_krb5_context> &context,
                                     string_view fullpath) noexcept
: Context(context)
, fullpath_(fullpath)
{
}

//------------------------------------------------------------------------------
FileInterface::~FileInterface() noexcept = default;

//------------------------------------------------------------------------------
bool FileInterface::FileExists() const noexcept
{
    bool res{false};
    string buf{fullpath_};

    try
    {
        const string prefix{"FILE:"};
        if (buf.rfind(prefix, 0) == 0)
        {
            buf.erase(0, prefix.length());
        }

        res = fs::exists(buf);
    }
    catch (const fs::filesystem_error &fs_error)
    {
        Logging::Error(
            "Ошибка доступа к файлу: {} ({})", buf, fs_error.what());
    }

    return res;
}

//------------------------------------------------------------------------------
const char *FileInterface::FileName() const noexcept
{
    return fullpath_.data();
}

//------------------------------------------------------------------------------
void FileInterface::Init() noexcept
{
    auto &cfg = configGlobal::instance();
    _program_type = cfg.variable("system/type", "manual");

    if (_fullpath.empty())
    {
        _fullpath = _program_type == "manual" ? defaultName() : configName();
    }
}

//------------------------------------------------------------------------------
std::string_view FileInterface::ProgramType() const noexcept
{
    return program_type_;
}

/*------------------------------------------------------------------------------
    Keytab
------------------------------------------------------------------------------*/
Keytab::Keytab(const shared_ptr<_krb5_context> &context,
                       string_view fullpath) noexcept
: FileInterface(context, fullpath)
{
    FileInterface::Init();

    auto error_code = krb5_kt_resolve(Context::GetContext(), FileName(), &keytab_);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_resolve");
    }
}

//------------------------------------------------------------------------------
Keytab::~Keytab() noexcept
{
    auto error_code = krb5_kt_close(GetContext(), keytab_);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_close");
    }
}

//------------------------------------------------------------------------------
shared_ptr<Creds> Keytab::GetCreds() const noexcept
{
    shared_ptr<Creds> creds_ptr{nullptr};

    auto principal = GetPrincipal();
    if (principal != nullptr)
    {
        krb5_creds creds;

        auto error_code = krb5_get_init_creds_keytab(
            GetContext(), &creds, principal->ptr(), keytab_, 0, nullptr, nullptr);
        if (error_code != 0)
        {
            PrintError(error_code, "krb5_get_init_creds_keytab");
        }

        creds_ptr = make_shared<Creds>(GetContextPtr(), creds);
    }

    return creds_ptr;
}

//------------------------------------------------------------------------------
shared_ptr<Principal> Keytab::GetPrincipal() const noexcept
{
    shared_ptr<Principal> principal{nullptr};

    krb5_keytab_entry entry;
    krb5_kt_cursor cursor{nullptr};
    auto error_code = krb5_kt_start_seq_get(GetContext(), keytab_, &cursor);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_start_seq_get");
        return principal;
    }

    error_code = krb5_kt_next_entry(GetContext(), keytab_, &entry, &cursor);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_next_entry");
    }

    error_code = krb5_kt_end_seq_get(GetContext(), keytab_, &cursor);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_end_seq_get");
    }

    principal = make_shared<Principal>(contextPtr(), entry.principal);

    error_code = krb5_kt_free_entry(GetContext(), &entry);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_free_entry");
    }

    return principal;
}

//------------------------------------------------------------------------------
string Keytab::DefaultName() const noexcept
{
    array<char, MAX_KEYTAB_NAME_LEN> fullpath{};
    auto error_code =
        krb5_kt_default_name(GetContext(), fullpath.data(), MAX_KEYTAB_NAME_LEN);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_kt_default_name");
    }

    return fullpath.data();
}

//------------------------------------------------------------------------------
string Keytab::ConfigName() const noexcept
{
    auto &cfg = configGlobal::instance();

    string fullpath = cfg.variable("system/progpath");
    fullpath = cfg.variable("kerberos/keytab", fullpath + "/keytab");

    return fullpath;
}

/*------------------------------------------------------------------------------
    Ccache
------------------------------------------------------------------------------*/
Ccache::Ccache(const shared_ptr<_krb5_context> &context,
                       string_view fullpath) noexcept
: FileInterface(context, fullpath)
{
    FileInterface::Init();

    setenv("KRB5CCNAME", FileName(), 1);

    auto error_code = krb5_cc_resolve(GetContext(), FileName(), &ccache_);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_cc_resolve");
    }
}

//------------------------------------------------------------------------------
Ccache::~Ccache() noexcept
{
    if (GetContext() != nullptr && ccache_ != nullptr)
    {
        krb5_error_code error_code{0};
        if (ProgramType() != "manual")
        {
            error_code = krb5_cc_destroy(GetContext(), ccache_);
        }
        else
        {
            error_code = krb5_cc_close(GetContext(), ccache_);
        }

        if (error_code != 0)
        {
            PrintError(error_code, "Ошибка закрытия или удаления Ccache");
        }
    }
}

//------------------------------------------------------------------------------
bool Ccache::Create(const shared_ptr<Principal> &principal,
                        const shared_ptr<Creds> &creds) const noexcept
{
    if (principal == nullptr || creds == nullptr)
    {
        return false;
    }

    auto error_code = krb5_cc_initialize(GetContext(), ccache_, principal->ptr());
    if (error_code != 0)
    {
        return false;
    }

    error_code = krb5_cc_store_cred(GetContext(), ccache_, creds->ptr());
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_cc_store_cred");
    }

    return error_code == 0;
}

//------------------------------------------------------------------------------
bool Ccache::Update() const noexcept
{
    auto principal = GetPrincipal();
    auto creds = GetCreds();
    if (principal == nullptr || creds == nullptr)
    {
        return false;
    }

    auto error_code = krb5_get_renewed_creds(
        GetContext(), creds->ptr(), principal->ptr(), ccache_, nullptr);
    if (error_code != 0)
    {
        PrintError(error_code, "krb5_get_renewed_creds");
        return false;
    }

    return Create(principal, creds);
}

//------------------------------------------------------------------------------
shared_ptr<Creds> Ccache::GetCreds() const noexcept
{
    shared_ptr<Creds> creds_ptr{nullptr};

    auto principal_client = GetPrincipal();
    if (principal_client == nullptr)
    {
        return creds_ptr;
    }

    auto principal_server = GetServerPrincipal(principal_client->realm());
    if (principal_client == nullptr)
    {
        return creds_ptr;
    }

    krb5_creds creds_find{};
    creds_find.client = principal_client->Ptr();
    creds_find.server = principal_server->Ptr();

    krb5_creds creds{};
    auto error_code =
        krb5_cc_retrieve_cred(GetContext(), ccache_, 0, &creds_find, &creds);
    if (error_code == 0)
    {
        creds_ptr = make_shared<Creds>(GetContextPtr(), creds);
    }
    else
    {
        PrintError(error_code, "krb5_cc_retrieve_cred");
    }

    return creds_ptr;
}

//------------------------------------------------------------------------------
shared_ptr<Principal> Ccache::GetPrincipal() const noexcept
{
    shared_ptr<Principal> principal_ptr{nullptr};

    krb5_principal principal{nullptr};
    auto error_code = krb5_cc_get_principal(GetContext(), ccache_, &principal);
    if (error_code == 0)
    {
        principal_ptr = make_shared<Principal>(GetContextPtr(), principal);
        krb5_free_principal(GetContext(), principal);
    }
    else
    {
        PrintError(error_code, "krb5_cc_get_principal");
    }

    return principal_ptr;
}

//------------------------------------------------------------------------------
shared_ptr<Principal> Ccache::GetServerPrincipal(
    string_view realm) const noexcept
{
    shared_ptr<Principal> principal_ptr{nullptr};

    krb5_principal principal{nullptr};

    auto error_code =
        krb5_build_principal_ext(GetContext(),
                                 &principal,
                                 static_cast<unsigned int>(realm.length()),
                                 realm.data(),
                                 KRB5_TGS_NAME_SIZE,
                                 KRB5_TGS_NAME,
                                 realm.length(),
                                 realm.data(),
                                 0);
    if (error_code == 0)
    {
        principal_ptr = make_shared<Principal>(GetContextPtr(), principal);
        krb5_free_principal(GetContext(), principal);
    }
    else
    {
        PrintError(error_code, "krb5_build_principal_ext");
    }

    return principal_ptr;
}

//------------------------------------------------------------------------------
string Ccache::DefaultName() const noexcept
{
    return krb5_cc_default_name(GetContext());
}

//------------------------------------------------------------------------------
string Ccache::ConfigName() const noexcept
{
    auto &cfg = configGlobal::instance();

    string fullpath = cfg.variable("system/progpath");
    fullpath = cfg.variable("kerberos/ccache", fullpath);
    fullpath += "/krb5cc_" + cfg.variable("system/progname");

    return fullpath;
}

/*------------------------------------------------------------------------------
    ServiceImpl
------------------------------------------------------------------------------*/
ServiceImpl::ServiceImpl() noexcept
{
    krb5_context context{nullptr};
    auto error_code = krb5_init_context(&context);
    if (error_code == 0)
    {
        const shared_ptr<_krb5_context> context_ptr{context, krb5_free_context};

        keytab_ = make_unique<Keytab>(context_ptr, keytab);
        ccache_ = make_unique<Ccache>(context_ptr, ccache);
    }
    else
    {
        Logging::Error("Ошибка при инициализации контекста Kerberos (krb5_init_context)");
    }
}

//------------------------------------------------------------------------------
ServiceImpl::~ServiceImpl() = default;

//------------------------------------------------------------------------------
bool ServiceImpl::CreateCcache() const noexcept
{
    const std::scoped_lock lock(_mutex);

    if (ccache_ == nullptr || keytab_ == nullptr)
    {
        return false;
    }

    Logging::Info("Создание Ccache");

    auto principal = keytab_->GetPrincipal();
    auto creds = keytab_->GetCreds();

    const bool res = ccache_->Create(principal, creds);
    if (res)
    {
        auto ccache_creds = ccache_->getCreds();
        Logging::Info("Время действия билета {}", ccache_creds->TimesInfo());
    }

    return res;
}

//------------------------------------------------------------------------------
bool ServiceImpl::UpdateCcache() const noexcept
{
    const std::scoped_lock lock(_mutex);

    if (ccache_ == nullptr)
    {
        return false;
    }

    if (!ccache_->FileExists())
    {
        return CreateCcache();
    }

    auto creds = ccache_->GetCreds();
    if (creds == nullptr)
    {
        return false;
    }

    bool res{false};
    switch (creds->State())
    {
        case Creds::STATE::RENEW:
            _log.tolog_info("Update ccache");
            res = _ccache->update();
            if (res)
            {
                auto ccache_creds = _ccache->getCreds();
                _log.tolog_info("Creds time\n%s", ccache_creds->timesInfo());
            }
            else
            {
                _log.tolog_info("Update ccache error. REINIT");
                res = createCcache();
            }
            break;

        case Creds::STATE::REINIT:
            res = createCcache();
            break;
        default:
            res = true;
            break;
    }

    return res;
}

}  // namespace tasp::krb5
