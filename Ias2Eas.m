clc
clear all
close all
%完成基于攻击面NHMM的MTD有效性评估工作
%%
%参数初始化
SimTime = 2000;
PCS.ospool = {'W','U','R'};
PCS.servicepool = {'A','N','I'};
PCS.ip = 200;
PCS.os = size(PCS.ospool,2);
PCS.service = size(PCS.servicepool,2);
PCS.mem = 2^16-1;
FRQ.ip = 100;
FRQ.os = 500;
FRQ.service = 300;
%根据CVE分析结果来给出已知漏洞的情况
VUL.os.W.num = 533;
VUL.os.U.num = 658;
VUL.os.R.num = 153;
VUL.os.W.exp = 6.0;
VUL.os.U.exp = 8.0;
VUL.os.R.exp = 8.4;
VUL.service.I.num = 1;
VUL.service.A.num = 16;
VUL.service.N.num = 1;
VUL.service.I.exp = 4.9;
VUL.service.A.exp = 9.5;
VUL.service.N.exp = 8.6;
INT.os.W = 7.4;
INT.os.U = 5.2;
INT.os.R = 6.1;
INT.service.I = 6.4;
INT.service.A = 3.5;
INT.service.N = 2.9;
%内攻击面初始化参数
IAS.ip = round(random('uniform',0,PCS.ip));
IAS.mem = round(random('uniform',0,PCS.mem));
IAS.os = PCS.ospool{round(random('uniform',1,PCS.os))};
IAS.service = PCS.servicepool{round(random('uniform',1,PCS.service))};
IAS.vulsize = round(random('uniform',10,100));
IAS.int = round(random('uniform',1,10));
IAS.con = 1;
%攻击者参数
ATT.abi = 1;%0.5为low，1为medium，2为high
ATT.obj.pr = 'admin';
%%
%基于参数生成MIAS序列
MIAS = {};
iasiploc = zeros(1,SimTime);
for t=1:SimTime
    
    if mod(t,FRQ.ip) == 1 && t ~= 1
        MIAS(t).Loc.ip = round(random('uniform',0,PCS.ip));
        IAS.ip = MIAS(t).Loc.ip;
    else
        MIAS(t).Loc.ip = IAS.ip;
    end
    if mod(t,FRQ.os) == 1 && t ~= 1
        MIAS(t).Omega.os = PCS.ospool{round(random('uniform',1,PCS.os))};
        IAS.os = MIAS(t).Omega.os;
        MIAS(t).Loc.mem = round(random('uniform',0,PCS.mem));
        IAS.mem = MIAS(t).Loc.mem;
    else
        MIAS(t).Omega.os = IAS.os;
        MIAS(t).Loc.mem = IAS.mem;
    end
    if mod(t,FRQ.service) == 1 && t ~= 1
        MIAS(t).Omega.service = PCS.servicepool{round(random('uniform',1,PCS.service))};
        IAS.service = MIAS(t).Omega.service;
        MIAS(t).Loc.mem = round(random('uniform',0,PCS.mem));
        IAS.mem = MIAS(t).Loc.mem;
    else
        MIAS(t).Omega.service = IAS.service;
        MIAS(t).Loc.mem = IAS.mem;
    end
    
    %     MIAS(t).Loc.mem = IAS.mem;
    switch MIAS(t).Omega.os
        case 'W'
            MIAS(t).Size.os.num = VUL.os.W.num;
            MIAS(t).Size.os.exp = VUL.os.W.exp;
            MIAS(t).Inten.os = INT.os.W;
        case 'U'
            MIAS(t).Size.os.num = VUL.os.U.num;
            MIAS(t).Size.os.exp = VUL.os.U.exp;
            MIAS(t).Inten.os = INT.os.U;
        case 'R'
            MIAS(t).Size.os.num = VUL.os.R.num;
            MIAS(t).Size.os.exp = VUL.os.R.exp;
            MIAS(t).Inten.os = INT.os.R;
    end
    switch MIAS(t).Omega.service
        case 'I'
            MIAS(t).Size.service.num = VUL.service.I.num;
            MIAS(t).Size.service.exp = VUL.service.I.exp;
            MIAS(t).Inten.service = INT.service.I;
        case 'A'
            MIAS(t).Size.service.num = VUL.service.A.num;
            MIAS(t).Size.service.exp = VUL.service.A.exp;
            MIAS(t).Inten.service = INT.service.A;
        case 'N'
            MIAS(t).Size.service.num = VUL.service.N.num;
            MIAS(t).Size.service.exp = VUL.service.N.exp;
            MIAS(t).Inten.service = INT.service.N;
    end
    MIAS(t).Conn = 1;
    iasiploc(t) = MIAS(t).Loc.ip;
end

%%
%根据MIAS的序列，生成MEAS序列的观测值
MEAS_obv = {};
ProTime = 1000;
easiploc_obv = zeros(1,SimTime);
block = 1;
pro = PoR(PCS.ip,SimTime,block,FRQ.ip);
pro_s = PoR(PCS.ip,SimTime,block,0);
pro_p = PoR(PCS.ip,SimTime,block,1);
profitx = 1:FRQ.ip:SimTime;
profity = pro(profitx);
lmd = 0.00692;
pro_exp = 1 - exp(-lmd*(1:SimTime));
pro_test = PoR(PCS.ip,SimTime,block,FRQ.ip);
prob = 1;
midprob = round(0.5*PCS.ip);
%
% for i = 1:ProTime
%     for t = 1:SimTime
%         if t <= FRQ.ip
%             pr_att_all(i,t) = random('uniform',pro_p(t),pro_s(t));
%         else
%             pr_att_all(i,t) = random('uniform',pro_p(t),pro_s(t));
%         end
%
%     end
% end

for t = 1:SimTime
    %     pr_att(t) = random('uniform',pro_p(prob),pro_s(prob));
    %     pr_att(t) = pr_att_all(round(random('uniform',1,ProTime)),prob);
    %     prob
    pr_att(t) = random('uniform',pro_p(prob),1);
    %     pr_att(t)
    if t == 1
        if pr_att(t) < pro(prob)
            MEAS_obv(t).Loc.ip = MIAS(t).Loc.ip;
        else
            MEAS_obv(t).Loc.ip = -1;
        end
        prob_obv_see(t) = prob;
        prob = prob + 1;
    else
        if MEAS_obv(t-1).Loc.ip == MIAS(t-1).Loc.ip && MEAS_obv(t-1).Loc.ip == MIAS(t).Loc.ip
            MEAS_obv(t).Loc.ip = MIAS(t).Loc.ip;
            prob = 1;
        else
            
            %             if prob <= midprob
            if pr_att(t) <= pro(prob)
                prob_obv(t) = prob;
                MEAS_obv(t).Loc.ip = MIAS(t).Loc.ip;
            else
                MEAS_obv(t).Loc.ip = -1;
            end
            %             else
            if pr_att(t) <= pro(prob)
                prob_obv(t) = prob;
                MEAS_obv(t).Loc.ip = MIAS(t).Loc.ip;
            else
                MEAS_obv(t).Loc.ip = -1;
            end
            %             end
            prob_obv_see(t) = prob;
            prob = prob + 1;
        end
    end
    
    
    
    
    easiploc_obv(t) = MEAS_obv(t).Loc.ip;
    
    if easiploc_obv(t) == iasiploc(t)
        attip_obv(t) =  iasiploc(t);
    else
        attip_obv(t) = -1;
    end
    
    
end
prob_obv_tnz = prob_obv(prob_obv ~=0 );



%%
%根据上一时刻MEAS(t-1)数据，生成MEAS(t)的数据，生成MEAS序列的预测值
MEAS_foc = {};
iniip = zeros(1,SimTime);
easiploc_foc = zeros(1,SimTime);
stos = zeros(1,SimTime);
stservice = zeros(1,SimTime);
for t = 1:SimTime
    if iniip(t) > PCS.ip
        iniip(t) = 0;
    end
    if t == 1
        %给出EAS的初始化结果
        if iniip(t) ==  MIAS(t).Loc.ip
            MEAS_foc(t).Loc.ip = iniip(t);
        else
            MEAS_foc(t).Loc.ip = -1;
        end
        MEAS_foc(t).Omega.os = -1;
        MEAS_foc(t).Omega.service = -1;
        MEAS_foc(t).Size.os.num = -1;
        MEAS_foc(t).Size.os.exp = -1;
        MEAS_foc(t).Size.service.num = -1;
        MEAS_foc(t).Size.service.exp = -1;
        MEAS_foc(t).Inten.os = -1;
        MEAS_foc(t).Inten.service = -1;
        MEAS_foc(t).Inten.privilege = 'guest';
        MEAS_foc(t).Loc.mem = -1;
        MEAS_foc(t).Conn = -1;
    else
        %攻击者获取并判断攻击面位置（Lnet）
        if MEAS_foc(t-1).Loc.ip == MIAS(t-1).Loc.ip && MEAS_foc(t-1).Loc.ip == MIAS(t).Loc.ip
            MEAS_foc(t).Loc.ip = MIAS(t).Loc.ip;
            
            iniip(t) = 0;
        elseif iniip(t) == MIAS(t).Loc.ip
            MEAS_foc(t).Loc.ip = MIAS(t).Loc.ip;
            iniip(t) = 0;
        else
            %             if mod(t,FRQ.ip) == 1 && t ~= 1
            %                 iniip(t) = 0;
            %             else
            iniip(t+1) = iniip(t) + 1;
            %             end
            %             MEAS_foc(t).Loc.ip = MEAS_foc(t-1).Loc.ip + 1;
            MEAS_foc(t).Loc.ip = -1;
            %             if MEAS_foc(t).Loc.ip > PCS.ip
            %                 MEAS_foc(t).Loc.ip = MEAS_foc(t).Loc.ip - PCS.ip;
            %             end
            
        end
        %攻击者获取并判断攻击面形状
        if MEAS_foc(t).Loc.ip ~= -1
            MEAS_foc(t).Omega = MIAS(t).Omega;
        else
            if MEAS_foc(t-1).Omega.os == MIAS(t-1).Omega.os && MEAS_foc(t-1).Omega.os == MIAS(t).Omega.os
                MEAS_foc(t).Omega.os = MIAS(t).Omega.os;
            else
                MEAS_foc(t).Omega.os = -1;
            end
            if MEAS_foc(t-1).Omega.service == MIAS(t-1).Omega.service && MEAS_foc(t-1).Omega.service == MIAS(t).Omega.service
                MEAS_foc(t).Omega.service = MIAS(t).Omega.service;
            else
                MEAS_foc(t).Omega.service = -1;
            end
        end
        %攻击者获取并判断攻击面大小
        if MEAS_foc(t).Omega.os ~= -1
            stos(t) = 1;
            MEAS_foc(t).Size.os.exp = MIAS(t).Size.os.exp;
            if mod(t,FRQ.os) ~= 0
                [~,stosp] = find(stos(FRQ.os*floor(t/FRQ.os)+1:t) ~=0);
            else
                [~,stosp] = find(stos(FRQ.os*(floor(t/FRQ.os)-1)+1:t) ~=0);
            end
            
            if isempty(stosp) ~= 1
                if mod(t,FRQ.os) ~= 0
                    if (mod(t,FRQ.os)-stosp(1)) * MIAS(t).Size.os.exp < MIAS(t).Size.os.num
                        MEAS_foc(t).Size.os.num = (mod(t,FRQ.os)-stosp(1)) * MIAS(t).Size.os.exp * ATT.abi;%MIAS(t).Size.os.num;
                    else
                        MEAS_foc(t).Size.os.num = MIAS(t).Size.os.num;
                    end
                else
                    if (t-stosp(1)) * MIAS(t).Size.os.exp < MIAS(t).Size.os.num
                        MEAS_foc(t).Size.os.num = (t-stosp(1)) * MIAS(t).Size.os.exp * ATT.abi;%MIAS(t).Size.os.num;
                    else
                        MEAS_foc(t).Size.os.num = MIAS(t).Size.os.num;
                    end
                end
            end
        else
            MEAS_foc(t).Size.os.exp = -1;
            MEAS_foc(t).Size.os.num = -1;
        end
        if MEAS_foc(t).Omega.service ~= -1
            stservice(t) = 1;
            MEAS_foc(t).Size.service.exp = MIAS(t).Size.service.exp;
            MEAS_foc(t).Size.service.num = MIAS(t).Size.service.num;
        else
            MEAS_foc(t).Size.service.exp = -1;
            MEAS_foc(t).Size.service.num = -1;
        end
        %攻击者获取并判断攻击面强度
        if MEAS_foc(t).Size.os.num == MIAS(t).Size.os.num && MEAS_foc(t).Size.service.num == MIAS(t).Size.service.num
            MEAS_foc(t).Inten.os = MIAS(t).Inten.os;
            MEAS_foc(t).Inten.service = MIAS(t).Inten.service;
        else
            MEAS_foc(t).Inten.os = -1;
            MEAS_foc(t).Inten.service = -1;
        end
        %攻击者获取并判断攻击面物理位置（Lphy）
        if MEAS_foc(t).Size.os.num == MIAS(t).Size.os.num && MEAS_foc(t).Size.service.num == MIAS(t).Size.service.num
            if MEAS_foc(t).Inten.os == MIAS(t).Inten.os && MEAS_foc(t).Inten.service == MIAS(t).Inten.service;
                MEAS_foc(t).Loc.mem = MIAS(t).Loc.mem;
            else
                MEAS_foc(t).Loc.mem = -1;
            end
        else
            MEAS_foc(t).Loc.mem = -1;
        end
        
        %攻击者获取并判断攻击面连接性
        if MEAS_foc(t).Loc.mem ~= -1 && MEAS_foc(t).Loc.ip ~= -1
            MEAS_foc(t).Conn = 1;
        else
            MEAS_foc(t).Conn = -1;
        end
        
    end
    
    
    easiploc_foc(t) = MEAS_foc(t).Loc.ip;
    if easiploc_foc(t) == iasiploc(t)
        attip_foc(t) =  iasiploc(t);
    else
        attip_foc(t) = -1;
    end
    eassizeservicenum(t) = MEAS_foc(t).Size.service.num;
    easlocmem(t) = MEAS_foc(t).Loc.mem;
end
prob_foc = zeros(1,SimTime);
overlap = 0;
for i = 1:SimTime
    
    if mod(i,FRQ.ip) == 0
        [~,pp] = find(attip_foc(i-FRQ.ip+1:i) ~=0);
        if ~isempty(pp)
            prob_foc(i) = overlap+pp(1);
            overlap = 0;
        else
            overlap = overlap + FRQ.ip;
        end
    end
end
prob_foc_tnz = prob_foc(prob_foc ~=0 );
%%
%原始数据展示
%
% plot(pro_exp)
% hold on
% % plot(pro)
% % plot(pro_p)
% % plot(pro_s)
figure(1);
plot(iasiploc,'+')
hold on
plot(easiploc_obv,'o')
plot(easiploc_foc,'.')
%
% % mean(prob_foc_tnz)
% % plot(prob_obv_tnz,'-.+')
% % hold on
% % plot(1:size(prob_obv_tnz,2),mean(prob_obv_tnz)*ones(1,size(prob_obv_tnz,2)),'--')
% % plot(prob_foc_tnz,'-.o')
% % plot(1:size(prob_foc_tnz,2),mean(prob_foc_tnz)*ones(1,size(prob_foc_tnz,2)),'-.')
%% 粒子滤波算法获取最终MEAS
% %initialize the variables
% N = 100; % 粒子数，越大效果越好，计算量也越大
% T = 10;
% x_V = 5;
% %initilize our initial, prior particle distribution as a gaussian around
% %the true initial value
%
% x_est_out = zeros(SimTime,T); % the vector of particle filter estimates.
% for simt = 1:SimTime
% %     x = 0;
%     x_P = zeros(1,N); % 粒子
%     % 用一个高斯分布随机的产生初始的粒子
%     for i = 1:N
%         x_P(i) = round(random('uniform',0,PCS.ip));%均匀分布
% %         x_U = (attip_obv(simt)+attip_foc(simt))/2;
% %         x_P(i) = abs(round(normrnd(attip_foc(simt),x_V)));%正态分布
%     end
%
% %     x_est = x; % time by time output of the particle filters estimate
%
%     for t = 1:T
%         x = attip_foc(simt);
%         z = attip_obv(simt);
%         %         x_P_update = zeros(1,N);
%         %         z_update = zeros(1,N);
%         x_P_update = x_P;
%         z_update = x_P_update;
%         for i = 1:N
% %             x_P_update(i) = x_P(i);
% %             z_update(i) = x_P_update(i);
%
%             %对每个粒子计算其权重
%             P_w(i) = (1/sqrt(abs(z_update(i)^2 - z^2)) + 1/sqrt(abs(z_update(i)^2 - x^2)))/2;
%         end
%         % 归一化.
%         %     P_w = P_w./sum(P_w);
%
%         % Resampling这里没有用博客里之前说的histc函数，不过目的和效果是一样的
%         P_w(isinf(P_w)) = 1;
%         for i = 1 : N
%             ii = find(random('uniform',0,sum(P_w)) <= cumsum(P_w),1);
%
%             x_P(i) = x_P_update(ii);   % 粒子权重大的将多得到后代
%
%
%         end                                                     % find( ,1) 返回第一个 符合前面条件的数的 下标
%
%         %状态估计，重采样以后，每个粒子的权重都变成了1/N
%         x_est = mean(x_P);
%
%         % Save data in arrays for later plotting
%         x_est_out(simt,t) = round(x_est);
%
%     end
%     simt
%     %     x_est
% end
% %
% %
% t = 1:T;
% simt = 1:SimTime;
% figure(2);
% clf
% plot(simt, attip_foc, '+b',simt, attip_obv, '.g', simt, x_est_out(:,T), 'or');
% set(gca,'FontSize',12); set(gcf,'Color','White');
% xlabel('time step'); ylabel('EAS ip position');
% legend('EAS ip forcast', 'EAS ip obv', 'EAS ip PF');
%%
% 根据MEAS分析攻击者的攻击阶段
% 给出基础判断规则
% R阶段为对攻击面位置和形状进行探索；
% W阶段对攻击面大小、强度进行研究；
% D阶段根据攻击面位置进行发送；
% E和I阶段依据攻击面大小、位置、形状和强度对节点进行攻击
% C&C和AoO阶段依据攻击面连接性对系统进行攻击
attphase = 7;
attstate = ones(7,SimTime);
attstate = -1 * attstate;
for t = 1:SimTime
    % R阶段判断
    if MEAS_foc(t).Loc.ip ~= -1 && MEAS_foc(t).Omega.os ~= -1 && MEAS_foc(t).Omega.service ~= -1
        attstate(1,t) = 1;
    else
        attstate(1,t) = 0;
    end
    % W阶段判断
    if MEAS_foc(t).Size.os.num == MIAS(t).Size.os.num && MEAS_foc(t).Size.service.num == MIAS(t).Size.service.num
        attstate(2,t) = 1;
    else
        attstate(2,t) = 0;
    end
    % D阶段判断
    if MEAS_foc(t).Loc.ip ~= -1
        attstate(3,t) = 1;
    else
        attstate(3,t) = 0;
    end
    % E阶段判断
    if MEAS_foc(t).Loc.mem ~= -1  && MEAS_foc(t).Size.os.num == MIAS(t).Size.os.num && MEAS_foc(t).Size.service.num == MIAS(t).Size.service.num && MEAS_foc(t).Omega.os ~= -1 && MEAS_foc(t).Omega.service ~= -1 
        attstate(4,t) = 1;
    else
        attstate(4,t) = 0;
    end
    % I阶段判断
    if  MEAS_foc(t).Size.os.num == MIAS(t).Size.os.num && MEAS_foc(t).Size.service.num == MIAS(t).Size.service.num && MEAS_foc(t).Omega.os ~= -1 && MEAS_foc(t).Omega.service ~= -1 
        attstate(5,t) = 1;
    else
        attstate(5,t) = 0;
    end
    % CnC阶段判断
    if MEAS_foc(t).Conn ~= -1
        attstate(6,t) = 1;
    else
        attstate(6,t) = 0;
    end
    % AoO阶段判断
    if 1
    end
    
    
    
end

plot(attstate(1,:),'.')
hold on

plot(attstate(2,:),'o')
plot(attstate(3,:),'+')
plot(attstate(4,:),'>')
plot(attstate(5,:),'^')
plot(attstate(6,:),'<')

