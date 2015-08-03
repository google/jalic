%{
% for sec = 80
n = 4000;
d=[(n+1):1:2^17];
D=[1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];
delta=[1.0081, 1.0081, 1.0084, 1.0084, 1.0088, 1.0088, 1.0092, 1.0092];
 %}

% for sec = 128
n = 1024
d=[(n+1):1:2^17];    
D=[1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];
delta=[1.0067, 1.0067, 1.0067, 1.0069, 1.0069, 1.0069, 1.0069, 1.0072];

min_i=2;
max_i=3;
for i=1:size(d, 2)
  if (d(i) > D(max_i))
    min_i = min_i + 1;
    max_i = max_i + 1;
  end
  temp = (d(i) - D(min_i)) / (D(max_i) - D(min_i));
  delta_d(i) = (1 - temp) * delta(min_i) + temp * delta(max_i);
end

minlogq = -d(1) * log2(1.5 / 3.2 / delta_d(1)^d(1)) / (d(1) - n);
mini = 1;
for i=2:size(d,2)
	logq = -d(i) * log2(1.5 / 3.2 / delta_d(i)^d(i)) / (d(i) - n);
  if (logq < minlogq)
    minlogq = logq;
    mini = i;
  end
end

minlogq
d(mini)
sqrt(n * minlogq / log2(delta_d(mini)))