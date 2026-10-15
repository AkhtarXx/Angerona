#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define RETAIN __attribute__((used))
#else
#define NOINLINE
#define RETAIN
#endif

namespace fixture {

constexpr std::uint32_t kMagic = 0xA617E20Fu;
constexpr const char* kBanner = "ANGERONA_COMPLEX_FIXTURE_v4";
constexpr const char* kEndpoint = "/api/v1/telemetry";
extern "C" {
RETAIN char kAuthOk[] = "AUTH_OK";
RETAIN char kAuthFail[] = "AUTH_FAIL";
}

struct PacketHeader {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t flags;
    std::uint32_t payload_size;
};

struct ParseResult {
    bool valid;
    std::uint32_t checksum;
    std::size_t consumed;
};

NOINLINE std::uint32_t checksum32(const std::uint8_t* data, std::size_t size) {
    std::uint32_t hash = 2166136261u;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
        hash = (hash << 5u) | (hash >> 27u);
    }
    return hash;
}

NOINLINE ParseResult parse_packet(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size < sizeof(PacketHeader)) {
        return {false, 0, 0};
    }
    PacketHeader header{};
    std::memcpy(&header, data, sizeof(header));
    if (header.magic != kMagic || header.version != 3) {
        return {false, 0, sizeof(header)};
    }
    const auto available = size - sizeof(header);
    if (header.payload_size > available || header.payload_size > 4096) {
        return {false, 0, sizeof(header)};
    }
    const auto* payload = data + sizeof(header);
    const auto digest = checksum32(payload, header.payload_size);
    return {true, digest, sizeof(header) + header.payload_size};
}

class Processor {
public:
    virtual ~Processor() = default;
    virtual std::uint32_t apply(std::uint32_t value) const = 0;
    virtual const char* name() const = 0;
};

class Auditable {
public:
    virtual ~Auditable() = default;
    virtual const char* audit_tag() const = 0;
};

class XorProcessor final : public Processor {
public:
    explicit XorProcessor(std::uint32_t key) : key_(key) {}
    NOINLINE std::uint32_t apply(std::uint32_t value) const override {
        return (value ^ key_) * 0x45D9F3Bu;
    }
    const char* name() const override { return "xor-processor"; }
private:
    std::uint32_t key_;
};

class RotateProcessor final : public Processor {
public:
    explicit RotateProcessor(unsigned shift) : shift_(shift & 31u) {}
    NOINLINE std::uint32_t apply(std::uint32_t value) const override {
        return (value << shift_) | (value >> ((32u - shift_) & 31u));
    }
    const char* name() const override { return "rotate-processor"; }
private:
    unsigned shift_;
};

class AuditedProcessor final : public Processor, public Auditable {
public:
    explicit AuditedProcessor(std::uint32_t key) : key_(key) {}
    NOINLINE std::uint32_t apply(std::uint32_t value) const override {
        return ((value ^ key_) << 9u) | ((value ^ key_) >> 23u);
    }
    const char* name() const override { return "audited-processor"; }
    const char* audit_tag() const override { return "audit-vmi"; }
private:
    std::uint32_t key_;
};

class VirtualAuditedProcessor final
    : public Processor,
      public virtual Auditable {
public:
    explicit VirtualAuditedProcessor(std::uint32_t key) : key_(key) {}
    NOINLINE std::uint32_t apply(std::uint32_t value) const override {
        const auto mixed = value + key_;
        return (mixed << 11u) | (mixed >> 21u);
    }
    const char* name() const override {
        return "virtual-audited-processor";
    }
    const char* audit_tag() const override {
        return "audit-virtual-base";
    }
private:
    std::uint32_t key_;
};

class VirtualAuditLayer : public virtual Auditable {
public:
    NOINLINE VirtualAuditLayer() = default;
    const char* audit_tag() const override {
        return "audit-layer";
    }
    virtual const char* layer_name() const {
        return "virtual-audit-layer";
    }
};

class DeepVirtualProcessor final
    : public Processor,
      public VirtualAuditLayer {
public:
    NOINLINE explicit DeepVirtualProcessor(std::uint32_t key) : key_(key) {}
    NOINLINE std::uint32_t apply(std::uint32_t value) const override {
        const auto mixed = value ^ key_;
        return (mixed << 13u) | (mixed >> 19u);
    }
    const char* name() const override {
        return "deep-virtual-processor";
    }
    const char* audit_tag() const override {
        return "audit-deep-virtual";
    }
    const char* layer_name() const override {
        return "deep-layer";
    }
private:
    std::uint32_t key_;
};

NOINLINE const char* read_audit_tag(const Auditable& auditable) {
    return auditable.audit_tag();
}

NOINLINE const char* read_layer_name(const VirtualAuditLayer& layer) {
    return layer.layer_name();
}

using Transform = std::uint32_t (*)(std::uint32_t);

NOINLINE std::uint32_t mix_add(std::uint32_t value) {
    return value + 0x9E3779B9u;
}

NOINLINE std::uint32_t mix_fold(std::uint32_t value) {
    value ^= value >> 16u;
    value *= 0x7FEB352Du;
    return value ^ (value >> 15u);
}

NOINLINE std::uint32_t indirect_pipeline(std::uint32_t seed, unsigned rounds) {
    static constexpr std::array<Transform, 2> transforms{mix_add, mix_fold};
    std::uint32_t value = seed;
    for (unsigned i = 0; i < rounds; ++i) {
        value = transforms[i & 1u](value);
    }
    return value;
}

NOINLINE int recursive_score(int value, int depth) {
    if (depth <= 0 || value <= 1) {
        return value;
    }
    return (value & 1)
        ? recursive_score(value - 1, depth - 1) + 3
        : recursive_score(value / 2, depth - 1) + 1;
}

NOINLINE std::uint32_t dispatch_command(unsigned command, std::uint32_t value) {
    switch (command) {
        case 0: return value;
        case 1: return value ^ 0xDEADBEEFu;
        case 2: return value + 0x10203040u;
        case 3: return value * 33u;
        case 4: return (value << 7u) | (value >> 25u);
        case 5: return checksum32(reinterpret_cast<const std::uint8_t*>(&value), sizeof(value));
        case 6: return indirect_pipeline(value, 5);
        case 7: return static_cast<std::uint32_t>(recursive_score(value & 0x7Fu, 8));
        default: return 0xFFFFFFFFu;
    }
}

NOINLINE std::vector<std::uint8_t> transform_buffer(
    const std::vector<std::uint8_t>& input,
    const Processor& processor
) {
    std::vector<std::uint8_t> output;
    output.reserve(input.size());
    std::uint32_t state = 0xC001D00Du;
    for (const auto byte : input) {
        state = processor.apply(state ^ byte);
        output.push_back(static_cast<std::uint8_t>(state & 0xFFu));
    }
    return output;
}

// Intentional benchmark sink (CWE-120). A guarded command-line path keeps it
// statically reachable from the process entry without triggering it during
// ordinary fixture execution.
extern "C" RETAIN NOINLINE void benchmark_unsafe_copy(char* destination, const char* source) {
    std::strcpy(destination, source);
}

NOINLINE std::string authenticate(const std::string& user, const std::string& token) {
    if (user == "admin" && token.size() == 16 && token.rfind("A6-", 0) == 0) {
        return kAuthOk;
    }
    return kAuthFail;
}

NOINLINE int run_fixture(int argc, char** argv) {
    std::puts(kBanner);
    std::puts(kEndpoint);

    const std::string user = argc > 1 ? argv[1] : "guest";
    const std::string token = argc > 2 ? argv[2] : "invalid";
    const auto auth = authenticate(user, token);
    std::puts(auth.c_str());

    if (argc > 4 && std::strcmp(argv[4], "unsafe-copy") == 0) {
        std::array<char, 16> destination{};
        benchmark_unsafe_copy(destination.data(), user.c_str());
        std::printf("copied=%s\n", destination.data());
    }

    std::vector<std::uint8_t> data{1, 3, 3, 7, 0xA6, 0x17, 0xE2, 0x0F};
    std::unique_ptr<Processor> processor;
    const Auditable* auditable = nullptr;
    const VirtualAuditLayer* audit_layer = nullptr;
    if (argc > 3 && std::strcmp(argv[3], "rotate") == 0) {
        processor = std::make_unique<RotateProcessor>(7);
    } else if (argc > 3 && std::strcmp(argv[3], "audited") == 0) {
        auto audited = std::make_unique<AuditedProcessor>(0x2468ACE0u);
        auditable = audited.get();
        processor = std::move(audited);
    } else if (
        argc > 3
        && std::strcmp(argv[3], "virtual-audited") == 0
    ) {
        auto virtual_audited = std::make_unique<VirtualAuditedProcessor>(
            0x10293847u
        );
        auditable = virtual_audited.get();
        processor = std::move(virtual_audited);
    } else if (
        argc > 3
        && std::strcmp(argv[3], "deep-virtual") == 0
    ) {
        auto deep = std::make_unique<DeepVirtualProcessor>(0x31415926u);
        auditable = deep.get();
        audit_layer = deep.get();
        processor = std::move(deep);
    } else {
        processor = std::make_unique<XorProcessor>(0x13579BDFu);
    }
    const auto transformed = transform_buffer(data, *processor);
    const auto score = dispatch_command(
        static_cast<unsigned>(argc) & 7u,
        checksum32(transformed.data(), transformed.size())
    );
    std::printf("processor=%s score=%08x bytes=%zu\n",
                processor->name(), score, transformed.size());
    if (auditable != nullptr) {
        std::printf("audit=%s\n", read_audit_tag(*auditable));
    }
    if (audit_layer != nullptr) {
        std::printf("layer=%s\n", read_layer_name(*audit_layer));
    }

    if (score == 0x11223344u) {
        throw std::runtime_error("unreachable benchmark exception");
    }
    return static_cast<int>(score & 0x7Fu);
}

}  // namespace fixture

int main(int argc, char** argv) {
    try {
        return fixture::run_fixture(argc, argv);
    } catch (const std::exception& exc) {
        std::fprintf(stderr, "fixture-error:%s\n", exc.what());
        return 2;
    }
}
