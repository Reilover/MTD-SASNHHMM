function [ por ] = PoR( PCS,Probtime,block,Frq )
%POR 此处显示有关此函数的摘要
%根据配置空间，探测次数，分块数和变化频率，给出攻击探测成功概率，用于计算MEAS_obv
%   此处显示详细说明
probm=0;
for prob = 1:Probtime
    if mod(prob,Frq)==0
        probm=prob/Frq;
    end
    pm_cs_vtt = pmcal(Frq,PCS,block);
    Pmj_cs_vtt = (1-pm_cs_vtt)^probm;
    Lr_cs_vtt = mod(prob,Frq);
    Pk_cs_vtt = plcal(Lr_cs_vtt,PCS,block);
    Pm_cs_vtt(prob) = 1 - Pmj_cs_vtt*(1-Pk_cs_vtt);
end
   por =  Pm_cs_vtt;
end

