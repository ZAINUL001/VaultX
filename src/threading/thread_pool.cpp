#include "vaultx/threading/thread_pool.hpp"

#include <stdexcept>
#include <utility>

namespace vaultx::threading {

ThreadPool::ThreadPool(size_t numThreads) {
    if (numThreads == 0) throw std::invalid_argument("ThreadPool needs at least 1 thread");
    workers_.reserve(numThreads);
    for (size_t i = 0; i < numThreads; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
    }
    cv_.notify_all();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
}

std::future<void> ThreadPool::submit(std::function<void()> task) {
    std::packaged_task<void()> packaged(std::move(task));
    std::future<void> fut = packaged.get_future();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) throw std::runtime_error("submit() on a stopped ThreadPool");
        tasks_.push(std::move(packaged));
    }
    cv_.notify_one();
    return fut;
}

void ThreadPool::workerLoop() {
    for (;;) {
        std::packaged_task<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
            if (tasks_.empty()) return;  // stopping and nothing left to do
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        task();  // exceptions are captured into the future
    }
}

}  // namespace vaultx::threading
