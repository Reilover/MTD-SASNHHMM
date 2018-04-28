function [ Pk ] = plcal( L,s,b )
%PLCAL 此处显示有关此函数的摘要
%   此处显示详细说明
if L<s*b && L>=b
    pk=[];
    for k=b:(L)
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
            Nk(k,t+1)=((-1)^t)*(nchoosek(b,t))*(bc);
        end
        pk(k)=(sum(Nk(k,:)))/(s^b);
        Nk=[];
    end
    Pk=sum(pk);
elseif L<b
    Pk=0;
elseif L>=s*b
    Pk=1;
end
end

