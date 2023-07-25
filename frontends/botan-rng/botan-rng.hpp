#ifndef ESDM_BOTAN_RNG_HPP
#define ESDM_BOTAN_RNG_HPP

#include <botan/rng.h>
#include <mutex>

class ESDM_RNG final : public Botan::RandomNumberGenerator {
public:
    // as long as prediction resistance is the only difference,
    // do not introduce multiple classes
    ESDM_RNG(bool prediction_resistance);

    ~ESDM_RNG();

    std::string name() const override;

    bool is_seeded() const override;

    bool accepts_input() const override;

    void clear() override;

protected:
    void fill_bytes_with_input(std::span<uint8_t> out,
                               std::span<const uint8_t> in) override;

private:
    const bool m_prediction_resistance;

    // ESDM rpc client locks concurrent accesses, but initialization should be
    // only done once
    static std::mutex m_init_lock;

    // counts how many ESDM RNG instances are active in order to perform init and
    // fini on first/last one
    static size_t m_ref_cnt;
};

#endif