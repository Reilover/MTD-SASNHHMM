function [ pm ] = pmcal( m,s,b )
%PMCAL 此处显示有关此函数的摘要
%   此处显示详细说明
pmtemp=[];
for k=b:m
    tmax1=floor((k-b)/s);
    tmax2=b;
    for t=0:tmax1
        bcmin1=k-b-s*t;
        bcmin2=b-1;
        if bcmin1>k-t*s-1
            bc=0;
        else
            bc=nchoosek(k-b-t*s,k-s*t-1);
        end
        if t>b
            Nk(k,t+1)=0;
        else
            Nk(k,t+1)=((-1)^t)*(nchoosek(b,t))*(bc);
        end
        
    end
    pmtemp(k)=(sum(Nk(k,:)))/(s^b);
    Nk=[];
end
pm=sum(pmtemp);

end

