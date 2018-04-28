function [ por ] = PoR( PCS,Probtime,block,Frq )
%POR �˴���ʾ�йش˺�����ժҪ
%�������ÿռ䣬̽��������ֿ����ͱ仯Ƶ�ʣ���������̽��ɹ����ʣ����ڼ���MEAS_obv
%   �˴���ʾ��ϸ˵��
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

