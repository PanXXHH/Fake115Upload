import time


def upload_progress(monitor):
    # 获取当前时间
    current_time = time.time()
    
    # 初始化一些静态变量
    if not hasattr(upload_progress, 'start_time'):
        upload_progress.start_time = current_time
        upload_progress.last_time = current_time
        upload_progress.last_bytes = 0

    # 计算当前时间与上次更新时间的差值
    elapsed_time = current_time - upload_progress.start_time
    interval_time = current_time - upload_progress.last_time

    # 每秒刷新一次
    if interval_time >= 1.0:
        bytes_read = monitor.bytes_read
        total_length = monitor.len
        progress_percentage = (bytes_read / total_length) * 100
        speed = (bytes_read - upload_progress.last_bytes) / interval_time / 1024  # 转换为KB/s

        # 计算剩余时间（基于当前速度）
        remaining_time = (total_length - bytes_read) / (speed * 1024) if speed > 0 else 0  # 转换速度回到bytes/s

        # 更新显示
        print(f"\r上传进度: {progress_percentage:.2f}% - {bytes_read}/{total_length} bytes, "
              f"速度: {speed:.2f} KB/s, 已用时: {elapsed_time:.2f}s, 预计剩余时间: {remaining_time:.2f}s", end="")

        # 重置最后更新时间和最后字节数
        upload_progress.last_time = current_time
        upload_progress.last_bytes = bytes_read