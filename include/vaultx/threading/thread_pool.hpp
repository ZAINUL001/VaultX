#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace vaultx::threading {

/// Fixed-size pool of worker threads fed by a shared task queue.
///
///   submit() --> [ task queue (mutex + condition_variable) ] --> worker 1..N
///
/// Each submit() returns a std::future<void>, so the caller can wait for the
/// task and any exception thrown inside a worker is re-thrown on get().
class ThreadPool {
public:
    explicit ThreadPool(size_t numThreads);
    ~ThreadPool();  // finishes queued tasks, then joins all workers

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    std::future<void> submit(std::function<void()> task);

    size_t size() const { return workers_.size(); }

private:
    void workerLoop();

    std::vector<std::thread> workers_;
    std::queue<std::packaged_task<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stopping_ = false;
};

}  // namespace vaultx::threading
