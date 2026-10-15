#include <stdexcept>

class Base {
public:
    virtual ~Base() = default;
    virtual int apply(int value) const = 0;
};

class Doubler final : public Base {
public:
    int apply(int value) const override { return value * 2; }
};

int invoke(const Base &object, int value) {
    if (value < 0) throw std::range_error("negative");
    return object.apply(value);
}

int main() {
    Doubler object;
    return invoke(object, 3);
}
